package collect

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"sentinela/internal/model"
)

// Arquivos maiores que isso não são "hasheados" (evita travar a varredura).
const maxHashSize = 256 << 20

// HRESULTs relevantes do WinVerifyTrust.
const (
	trustENoSignature       = 0x800B0100
	trustESubjectFormUnknwn = 0x800B0003
	trustEProviderUnknown   = 0x800B0001
	trustEBadDigest         = 0x80096010
	trustEExplicitDistrust  = 0x800B0111
	certEExpired            = 0x800B0101
	certEUntrustedRoot      = 0x800B0109
	certERevoked            = 0x800B010C
	cryptEFileError         = 0x80092003
)

var (
	modwintrust = windows.NewLazySystemDLL("wintrust.dll")
	modcrypt32  = windows.NewLazySystemDLL("crypt32.dll")

	procCATAdminAcquireContext2         = modwintrust.NewProc("CryptCATAdminAcquireContext2")
	procCATAdminCalcHashFromFileHandle2 = modwintrust.NewProc("CryptCATAdminCalcHashFromFileHandle2")
	procCATAdminEnumCatalogFromHash     = modwintrust.NewProc("CryptCATAdminEnumCatalogFromHash")
	procCATCatalogInfoFromContext       = modwintrust.NewProc("CryptCATCatalogInfoFromContext")
	procCATAdminReleaseCatalogContext   = modwintrust.NewProc("CryptCATAdminReleaseCatalogContext")
	procCATAdminReleaseContext          = modwintrust.NewProc("CryptCATAdminReleaseContext")

	procCryptMsgGetParam = modcrypt32.NewProc("CryptMsgGetParam")
	procCryptMsgClose    = modcrypt32.NewProc("CryptMsgClose")
)

type catalogInfo struct {
	Size        uint32
	CatalogFile [windows.MAX_PATH]uint16
}

type wintrustCatalogInfo struct {
	Size                   uint32
	CatalogVersion         uint32
	CatalogFilePath        *uint16
	MemberTag              *uint16
	MemberFilePath         *uint16
	MemberFile             windows.Handle
	CalculatedFileHash     *byte
	CalculatedFileHashSize uint32
	CatalogContext         uintptr
	CatAdmin               uintptr
}

// Prefixo de CMSG_SIGNER_INFO (só precisamos de Issuer e SerialNumber).
type cmsgSignerInfo struct {
	Version      uint32
	Issuer       windows.CertNameBlob
	SerialNumber windows.CryptIntegerBlob
}

const cmsgSignerInfoParam = 6

// Inspector coleta e mantém em cache as informações de arquivos durante uma
// varredura (o mesmo executável costuma aparecer várias vezes).
type Inspector struct {
	mu       sync.Mutex
	cache    map[string]*model.FileInfo
	catAdmin map[string]uintptr
}

func NewInspector() *Inspector {
	return &Inspector{cache: map[string]*model.FileInfo{}, catAdmin: map[string]uintptr{}}
}

func (in *Inspector) Close() {
	for _, h := range in.catAdmin {
		if h != 0 {
			procCATAdminReleaseContext.Call(h, 0)
		}
	}
	in.catAdmin = map[string]uintptr{}
}

// Inspect retorna as informações de um arquivo. path vazio retorna nil.
func (in *Inspector) Inspect(path string) *model.FileInfo {
	if path == "" {
		return nil
	}
	key := strings.ToLower(path)
	in.mu.Lock()
	if fi, ok := in.cache[key]; ok {
		in.mu.Unlock()
		return fi
	}
	in.mu.Unlock()

	fi := in.inspect(path)

	in.mu.Lock()
	in.cache[key] = fi
	in.mu.Unlock()
	return fi
}

func (in *Inspector) inspect(path string) *model.FileInfo {
	fi := &model.FileInfo{Path: path}
	st, err := os.Stat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			fi.Error = err.Error()
		}
		return fi
	}
	if st.IsDir() {
		fi.Error = "é um diretório"
		return fi
	}
	fi.Exists = true
	fi.Size = st.Size()
	fi.Modified = st.ModTime().UTC()
	if attr, ok := st.Sys().(*syscall.Win32FileAttributeData); ok {
		fi.Created = time.Unix(0, attr.CreationTime.Nanoseconds()).UTC()
	}

	if fi.Size <= maxHashSize {
		if h, err := hashFile(path); err == nil {
			fi.SHA256 = h
		} else {
			fi.Error = "hash: " + err.Error()
		}
	} else {
		fi.Error = fmt.Sprintf("arquivo grande demais para hash (%d MB)", fi.Size>>20)
	}

	readVersionInfo(path, fi)
	in.verifySignature(path, fi)
	return fi
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// HashFile é exportado para a remediação (confere o hash antes de agir).
func HashFile(path string) (string, error) { return hashFile(path) }

// ---------------------------------------------------------------------------
// Assinatura digital

func winVerify(choice uint32, ptr unsafe.Pointer) uint32 {
	data := windows.WinTrustData{
		Size:                            uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_NONE,
		UnionChoice:                     choice,
		FileOrCatalogOrBlobOrSgnrOrCert: ptr,
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		// Sem acesso à rede durante a verificação: a varredura precisa ser
		// rápida e funcionar offline.
		ProvFlags: windows.WTD_REVOCATION_CHECK_NONE | windows.WTD_CACHE_ONLY_URL_RETRIEVAL,
	}
	action := windows.WINTRUST_ACTION_GENERIC_VERIFY_V2
	err := windows.WinVerifyTrustEx(0, &action, &data)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	windows.WinVerifyTrustEx(0, &action, &data)
	if err == nil {
		return 0
	}
	if e, ok := err.(syscall.Errno); ok {
		return uint32(e)
	}
	return 0xFFFFFFFF
}

func (in *Inspector) verifySignature(path string, fi *model.FileInfo) {
	p16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		fi.Signature = "error"
		return
	}
	file := windows.WinTrustFileInfo{
		Size:     uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})),
		FilePath: p16,
	}
	status := winVerify(windows.WTD_CHOICE_FILE, unsafe.Pointer(&file))

	switch status {
	case 0:
		fi.Signature = "valid"
		fi.Signer = signerFromFile(path)
		return
	case trustENoSignature, trustESubjectFormUnknwn, trustEProviderUnknown:
		// Sem assinatura embutida: tenta o catálogo do Windows (é assim que
		// a maioria dos binários do sistema é assinada).
		if catFile, st, found := in.verifyCatalog(path); found {
			fi.CatalogSigned = true
			if st == 0 {
				fi.Signature = "valid"
			} else {
				fi.Signature = "invalid"
				fi.Error = joinErr(fi.Error, trustReason(st))
			}
			fi.Signer = signerFromFile(catFile)
			return
		}
		fi.Signature = "unsigned"
	case cryptEFileError:
		fi.Signature = "error"
		fi.Error = joinErr(fi.Error, "não foi possível ler o arquivo para verificar a assinatura")
	default:
		// Assinatura presente mas inválida (adulterada, revogada, raiz não
		// confiável...). Ainda mostramos quem "diz" ter assinado.
		fi.Signature = "invalid"
		fi.Signer = signerFromFile(path)
		fi.Error = joinErr(fi.Error, trustReason(status))
	}
}

func trustReason(st uint32) string {
	switch st {
	case trustEBadDigest:
		return "assinatura não corresponde ao conteúdo (arquivo adulterado)"
	case trustEExplicitDistrust:
		return "certificado explicitamente não confiável"
	case certEExpired:
		return "certificado expirado"
	case certEUntrustedRoot:
		return "cadeia de certificados com raiz não confiável"
	case certERevoked:
		return "certificado revogado"
	}
	return fmt.Sprintf("falha na verificação da assinatura (0x%08X)", st)
}

func joinErr(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

func (in *Inspector) admin(alg string) uintptr {
	if h, ok := in.catAdmin[alg]; ok {
		return h
	}
	var h uintptr
	algp, _ := windows.UTF16PtrFromString(alg)
	r, _, _ := procCATAdminAcquireContext2.Call(uintptr(unsafe.Pointer(&h)), 0, uintptr(unsafe.Pointer(algp)), 0, 0)
	if r == 0 {
		h = 0
	}
	in.catAdmin[alg] = h
	return h
}

// verifyCatalog procura o arquivo nos catálogos do sistema. Retorna o
// caminho do catálogo, o status da verificação e se foi encontrado.
func (in *Inspector) verifyCatalog(path string) (string, uint32, bool) {
	if procCATAdminAcquireContext2.Find() != nil {
		return "", 0, false
	}
	f, err := os.Open(path)
	if err != nil {
		return "", 0, false
	}
	defer f.Close()

	for _, alg := range []string{"SHA256", "SHA1"} {
		adm := in.admin(alg)
		if adm == 0 {
			continue
		}
		size := uint32(64)
		hash := make([]byte, size)
		f.Seek(0, io.SeekStart)
		r, _, _ := procCATAdminCalcHashFromFileHandle2.Call(adm, f.Fd(),
			uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&hash[0])), 0)
		if r == 0 || size == 0 {
			continue
		}
		hash = hash[:size]
		ci, _, _ := procCATAdminEnumCatalogFromHash.Call(adm, uintptr(unsafe.Pointer(&hash[0])), uintptr(size), 0, 0)
		if ci == 0 {
			continue
		}
		info := catalogInfo{Size: uint32(unsafe.Sizeof(catalogInfo{}))}
		r, _, _ = procCATCatalogInfoFromContext.Call(ci, uintptr(unsafe.Pointer(&info)), 0)
		if r == 0 {
			procCATAdminReleaseCatalogContext.Call(adm, ci, 0)
			continue
		}
		catFile := windows.UTF16ToString(info.CatalogFile[:])
		catP, _ := windows.UTF16PtrFromString(catFile)
		tagP, _ := windows.UTF16PtrFromString(strings.ToUpper(hex.EncodeToString(hash)))
		memP, _ := windows.UTF16PtrFromString(path)
		wci := wintrustCatalogInfo{
			Size:                   uint32(unsafe.Sizeof(wintrustCatalogInfo{})),
			CatalogFilePath:        catP,
			MemberTag:              tagP,
			MemberFilePath:         memP,
			CalculatedFileHash:     &hash[0],
			CalculatedFileHashSize: size,
			CatAdmin:               adm,
		}
		st := winVerify(windows.WTD_CHOICE_CATALOG, unsafe.Pointer(&wci))
		procCATAdminReleaseCatalogContext.Call(adm, ci, 0)
		return catFile, st, true
	}
	return "", 0, false
}

// signerFromFile extrai o nome do assinante de um PE assinado ou de um .cat.
func signerFromFile(path string) string {
	p16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return ""
	}
	var encoding, contentType, formatType uint32
	var store, msg windows.Handle
	err = windows.CryptQueryObject(windows.CERT_QUERY_OBJECT_FILE, unsafe.Pointer(p16),
		windows.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED|windows.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
		windows.CERT_QUERY_FORMAT_FLAG_BINARY, 0, &encoding, &contentType, &formatType, &store, &msg, nil)
	if err != nil {
		return ""
	}
	defer windows.CertCloseStore(store, 0)
	defer procCryptMsgClose.Call(uintptr(msg))

	var size uint32
	r, _, _ := procCryptMsgGetParam.Call(uintptr(msg), cmsgSignerInfoParam, 0, 0, uintptr(unsafe.Pointer(&size)))
	if r == 0 || size < uint32(unsafe.Sizeof(cmsgSignerInfo{})) {
		return ""
	}
	// []uint64 garante alinhamento de 8 bytes para a estrutura.
	buf := make([]uint64, (size+7)/8)
	r, _, _ = procCryptMsgGetParam.Call(uintptr(msg), cmsgSignerInfoParam, 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r == 0 {
		return ""
	}
	si := (*cmsgSignerInfo)(unsafe.Pointer(&buf[0]))
	ci := windows.CertInfo{Issuer: si.Issuer, SerialNumber: si.SerialNumber}
	cert, err := windows.CertFindCertificateInStore(store,
		windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING, 0,
		windows.CERT_FIND_SUBJECT_CERT, unsafe.Pointer(&ci), nil)
	if err != nil || cert == nil {
		return ""
	}
	defer windows.CertFreeCertificateContext(cert)
	name := make([]uint16, 256)
	n := windows.CertGetNameString(cert, windows.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil, &name[0], uint32(len(name)))
	if n <= 1 {
		return ""
	}
	return windows.UTF16ToString(name[:n])
}

// ---------------------------------------------------------------------------
// Recurso de versão (fabricante, produto, descrição)

func readVersionInfo(path string, fi *model.FileInfo) {
	size, err := windows.GetFileVersionInfoSize(path, nil)
	if err != nil || size == 0 {
		return
	}
	buf := make([]byte, size)
	if err := windows.GetFileVersionInfo(path, 0, size, unsafe.Pointer(&buf[0])); err != nil {
		return
	}
	block := unsafe.Pointer(&buf[0])

	var langs []string
	var p unsafe.Pointer
	var l uint32
	if windows.VerQueryValue(block, `\VarFileInfo\Translation`, unsafe.Pointer(&p), &l) == nil && l >= 4 {
		n := int(l / 4)
		pairs := unsafe.Slice((*uint16)(p), n*2)
		for i := 0; i < n; i++ {
			langs = append(langs, fmt.Sprintf("%04x%04x", pairs[i*2], pairs[i*2+1]))
		}
	}
	langs = append(langs, "040904b0", "040904e4", "041604b0", "000004b0")

	get := func(key string) string {
		for _, lg := range langs {
			var vp unsafe.Pointer
			var vl uint32
			if windows.VerQueryValue(block, `\StringFileInfo\`+lg+`\`+key, unsafe.Pointer(&vp), &vl) == nil && vl > 0 {
				return strings.TrimSpace(windows.UTF16PtrToString((*uint16)(vp)))
			}
		}
		return ""
	}
	fi.Company = get("CompanyName")
	fi.Product = get("ProductName")
	fi.Description = get("FileDescription")
	fi.OriginalFilename = get("OriginalFilename")
}
