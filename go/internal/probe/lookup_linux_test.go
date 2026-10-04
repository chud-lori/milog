//go:build linux

package probe

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

// renameThread names one non-leader OS thread and holds it until release closes.
func renameThread(t *testing.T, name string, release <-chan struct{}) int {
	t.Helper()
	for i := 0; i < 4; i++ {
		tidCh := make(chan int)
		go func() {
			// Never unlocked, so the renamed thread exits with this goroutine.
			runtime.LockOSThread()
			tid := syscall.Gettid()
			if tid != os.Getpid() {
				b := append([]byte(name), 0)
				syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_SET_NAME, uintptr(unsafe.Pointer(&b[0])), 0)
			}
			tidCh <- tid
			<-release
		}()
		if tid := <-tidCh; tid != os.Getpid() {
			return tid
		}
	}
	t.Fatal("could not get a non-leader thread")
	return 0
}

func TestLookupProc_NamesLeaderNotThread(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	pid := os.Getpid()
	tid := renameThread(t, "ParseLoop", release)

	threadComm, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/task/" + strconv.Itoa(tid) + "/comm")
	if err != nil || strings.TrimSpace(string(threadComm)) != "ParseLoop" {
		t.Fatalf("thread rename did not take: %q %v", threadComm, err)
	}
	leaderComm, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
	if err != nil {
		t.Fatal(err)
	}

	ppid, _, procComm := lookupProc(uint32(pid))
	if procComm != strings.TrimSpace(string(leaderComm)) || procComm == "ParseLoop" {
		t.Errorf("procComm = %q, want leader name %q", procComm, strings.TrimSpace(string(leaderComm)))
	}
	if int(ppid) != os.Getppid() {
		t.Errorf("ppid = %d, want %d", ppid, os.Getppid())
	}
}

func TestLookupExeCgroup_Self(t *testing.T) {
	exe, cgroup := lookupExeCgroup(uint32(os.Getpid()))
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if want, _ := filepath.EvalSymlinks(self); exe != want {
		t.Errorf("exe = %q, want %q", exe, want)
	}
	if !strings.HasPrefix(cgroup, "/") {
		t.Errorf("cgroup = %q, want an absolute cgroup path", cgroup)
	}
	if exe, cgroup := lookupExeCgroup(0); exe != "" || cgroup != "" {
		t.Errorf("missing pid should give empty strings, got %q %q", exe, cgroup)
	}
}
