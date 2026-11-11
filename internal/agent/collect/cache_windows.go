package collect

import (
	"encoding/json"
	"hash/fnv"
	"os"
	"path/filepath"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"sentinela/internal/model"
)

// Cache da análise de arquivos.
//
// Analisar um arquivo custa caro (o SHA-256 lê o arquivo inteiro e a
// assinatura é verificada pelo Windows). O resultado fica em cache e só é
// refeito quando o arquivo muda. "Mudou" é decidido por:
//   - tamanho e data de modificação;
//   - ChangeTime do NTFS, que o sistema atualiza a cada escrita e que, ao
//     contrário da data de modificação, não é alterado pela API comum de
//     datas (SetFileTime) usada para disfarçar um arquivo trocado;
//   - validade: mesmo sem mudança aparente, tudo é refeito a cada ~24 h.

// cacheSchema muda quando a análise ganha campos novos: entradas salvas por
// uma versão anterior são descartadas e os arquivos, analisados de novo.
const cacheSchema = 3

const (
	cacheTTL    = 20 * time.Hour
	cacheJitter = 8 * time.Hour // espalha as reanálises (20 h a 28 h)
	cacheMax    = 20000
)

type cacheEntry struct {
	FI      *model.FileInfo `json:"fi"`
	Size    int64           `json:"size"`
	Write   int64           `json:"write"`  // LastWriteTime (FILETIME)
	Change  int64           `json:"change"` // ChangeTime (FILETIME)
	Checked time.Time       `json:"checked"`
}

// fileStamp é o "carimbo" de um arquivo, lido sem abrir o conteúdo (não
// dispara a leitura pelo antivírus e funciona com arquivos em uso).
type fileStamp struct {
	Size                  int64
	Created, Write, Change int64
	Attrs                 uint32
	Dir                   bool
}

type fileBasicInfo struct {
	CreationTime, LastAccessTime, LastWriteTime, ChangeTime int64
	FileAttributes                                          uint32
	_                                                       uint32
}

type fileStandardInfo struct {
	AllocationSize, EndOfFile int64
	NumberOfLinks             uint32
	DeletePending, Directory  bool
	_                         [2]byte
}

func stampFile(path string) (fileStamp, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fileStamp{}, err
	}
	h, err := windows.CreateFile(p, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return fileStamp{}, err
	}
	defer windows.CloseHandle(h)
	var bi fileBasicInfo
	if err := windows.GetFileInformationByHandleEx(h, windows.FileBasicInfo, (*byte)(unsafe.Pointer(&bi)), uint32(unsafe.Sizeof(bi))); err != nil {
		return fileStamp{}, err
	}
	var si fileStandardInfo
	if err := windows.GetFileInformationByHandleEx(h, windows.FileStandardInfo, (*byte)(unsafe.Pointer(&si)), uint32(unsafe.Sizeof(si))); err != nil {
		return fileStamp{}, err
	}
	return fileStamp{Size: si.EndOfFile, Created: bi.CreationTime, Write: bi.LastWriteTime,
		Change: bi.ChangeTime, Attrs: bi.FileAttributes, Dir: si.Directory}, nil
}

// filetime converte FILETIME (100 ns desde 1601) para time.Time.
func filetime(ft int64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	return time.Unix(0, (ft-116444736000000000)*100).UTC()
}

func entryTTL(key string) time.Duration {
	h := fnv.New32a()
	h.Write([]byte(key))
	return cacheTTL + time.Duration(h.Sum32()%uint32(cacheJitter/time.Minute))*time.Minute
}

// fresh diz se a entrada do cache ainda vale para o arquivo atual.
func (e *cacheEntry) fresh(key string, st fileStamp, err error, now time.Time) bool {
	if now.Sub(e.Checked) > entryTTL(key) {
		return false
	}
	if err != nil {
		return !e.FI.Exists && os.IsNotExist(err)
	}
	return e.FI.Exists && st.Size == e.Size && st.Write == e.Write && st.Change == e.Change
}

type cacheFile struct {
	Schema  int                    `json:"schema"`
	Saved   time.Time              `json:"saved"`
	Entries map[string]*cacheEntry `json:"entries"`
}

// SaveCache grava o cache em disco (só arquivos existentes e sem erro).
func (in *Inspector) SaveCache(path string) error {
	in.mu.Lock()
	out := cacheFile{Schema: cacheSchema, Saved: time.Now().UTC(), Entries: make(map[string]*cacheEntry, len(in.cache))}
	for k, e := range in.cache {
		if e.FI != nil && e.FI.Exists && e.FI.Error == "" {
			out.Entries[k] = e
		}
	}
	in.mu.Unlock()
	b, err := json.Marshal(out)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadCache carrega um cache salvo. Entradas de outra versão são ignoradas.
func (in *Inspector) LoadCache(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var cf cacheFile
	if err := json.Unmarshal(b, &cf); err != nil || cf.Schema != cacheSchema {
		return 0, err
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	n := 0
	for k, e := range cf.Entries {
		if e != nil && e.FI != nil && len(in.cache) < cacheMax {
			in.cache[k] = e
			n++
		}
	}
	return n, nil
}

// CachePath é onde o agente guarda o cache dentro da pasta de dados.
func CachePath(dataDir string) string { return filepath.Join(dataDir, "filecache.json") }

// ---------------------------------------------------------------------------
// Prioridade baixa para a varredura

var procSetThreadPriority = windows.NewLazySystemDLL("kernel32.dll").NewProc("SetThreadPriority")

const (
	threadModeBackgroundBegin = 0x00010000
	threadModeBackgroundEnd   = 0x00020000
)

// Background coloca a goroutine atual numa thread em "modo background" do
// Windows (CPU, disco e memória com prioridade baixa) até a função devolvida
// ser chamada. O monitor em tempo real, em outras threads, não é afetado.
func Background() (end func()) {
	runtime.LockOSThread()
	cur, _ := windows.GetCurrentThread()
	r, _, _ := procSetThreadPriority.Call(uintptr(cur), threadModeBackgroundBegin)
	return func() {
		if r != 0 {
			procSetThreadPriority.Call(uintptr(cur), threadModeBackgroundEnd)
		}
		runtime.UnlockOSThread()
	}
}
