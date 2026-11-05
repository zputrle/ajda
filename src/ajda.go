package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	libseccomp "github.com/seccomp/libseccomp-golang"
)

// File wrapper used to synchronize access to a file descriptor
type FileWrap struct {
	lock sync.Mutex
	fd   *os.File
}

func Wrap(f *os.File) *FileWrap {
	return &FileWrap{fd: f, lock: sync.Mutex{}}
}

func (fw *FileWrap) CopyTo(dst io.Writer) (int64, error) {
	fw.lock.Lock()
	defer fw.lock.Unlock()

	_, err := fw.fd.Seek(0, io.SeekStart)
	if err != nil {
		return 0, fmt.Errorf("Failed to move file descriptor's offset to start of the file: %w", err)
	}

	cnt, err := io.Copy(dst, fw.fd)
	if err != nil {
		return cnt, fmt.Errorf("Error occurred while coping the file: %w", err)
	}

	return cnt, err
}

// Default response when file cannot be served.
func CannotBeServed(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(404)
	w.Write([]byte("404 resource not found\n"))
}

// Allow only the following system calls.
func whiteList(syscalls []string) error {

	slog.Info("Whitelisting system calls.", "system_calls", strings.Join(syscalls, ", "))

	filter, err := libseccomp.NewFilter(libseccomp.ActErrno.SetReturnCode(int16(syscall.EPERM)))
	if err != nil {
		return err
	}
	for _, element := range syscalls {
		syscallID, err := libseccomp.GetSyscallFromName(element)
		if err != nil {
			return err
		}
		err = filter.AddRule(syscallID, libseccomp.ActAllow)
		if err != nil {
			return err
		}
	}
	return filter.Load()
}

// Set memory to the number of <n_cores> and memory to <memroy_size> in bytes.
func limit_memory_and_cpu(n_cores int, memory_size int) error {

	slog.Info("Limiting the number of cores and memory.", "#cores", n_cores, "memory(MB)", memory_size)

	uid := os.Getuid()
	cgroupRoot := fmt.Sprintf("/sys/fs/cgroup/user.slice/user-%d.slice/user@%d.service/app.slice/", uid, uid)
	cgroupName := "ajda.service"
	cgroupPath := filepath.Join(cgroupRoot, cgroupName)

	// Create cgroup.cgroupRoot
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		return fmt.Errorf("Failed to create cgroup: %w", err)
	}

	// Set memory limit.
	if err := os.WriteFile(
		filepath.Join(cgroupPath, "memory.max"),
		[]byte(fmt.Sprintf("%d", memory_size*1024*1024)),
		0644,
	); err != nil {
		return fmt.Errorf("Failed to set memory limit: %w", err)
	}

	if err := os.WriteFile(
		filepath.Join(cgroupPath, "cpu.max"),
		[]byte(fmt.Sprintf("%d 100000", n_cores*100000)),
		0644,
	); err != nil {
		return fmt.Errorf("Failed to set cpu limit: %w", err)
	}

	// Set the number of gorutines that can run in parallel.
	runtime.GOMAXPROCS(n_cores)

	// Move this process into the cgroup.
	pid := os.Getpid()
	//slog.Info("Adding PID to cgroup.", "pid", pid)
	if err := os.WriteFile(
		filepath.Join(cgroupPath, "cgroup.procs"),
		[]byte(fmt.Sprintf("%d", pid)),
		0644,
	); err != nil {
		return fmt.Errorf("Failed to add process to the group: %w", err)
	}

	return nil
}

func randomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// Serve only allowed paths.
func ServeOnly(availableFiles map[string]*FileWrap, home string) func(http.ResponseWriter, *http.Request) {

	return func(w http.ResponseWriter, req *http.Request) {

		id, err := randomHex(3)
		if err != nil {
			panic(fmt.Sprintf("Failed to generate a valid ID for a request: %v", err))
		}

		// Setup request specific logger.
		log := slog.With("req_id", id)

		path := req.URL.Path

		log.Info("Received request.", "path", path, "from", req.RemoteAddr)

		// Redirect to home page if "/" path provided.
		if path == "/" {
			slog.Info("Redirecting.", "to", home)
			http.Redirect(w, req, home, http.StatusFound)
			return
		}

		// Check if the requested file is available.
		fw, ok := availableFiles[path]
		if !ok {
			log.Warn("File not available.", "path", path)
			CannotBeServed(w)
			return
		}

		pathSpl := strings.Split(path, ".")
		if len(pathSpl) != 2 {
			log.Warn("Invalid path format. Expecting only one dot.", "path", path)
			CannotBeServed(w)
			return
		}

		// Check the file type.
		fileType := pathSpl[1]
		switch fileType {
		case "html":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
		case "css":
			w.Header().Set("Content-Type", "text/css")
		case "png":
			w.Header().Set("Content-Type", "image/png")
		case "svg":
			w.Header().Set("Content-Type", "image/svg")
		case "txt":
			w.Header().Set("Content-Type", "text/plain")
		default:
			log.Error("Invalid file type.", "type", fileType)
			CannotBeServed(w)
			return
		}

		if len(path) > 0 && path[0] != '/' {
			log.Error("Path does not start with '/'.", "path", path)
			CannotBeServed(w)
			return
		}

		_, err = fw.CopyTo(w)
		if err != nil {
			log.Error("Failed to send a file.", "error", err)
			CannotBeServed(w)
			return
		}
	}
}

func constructTLSListener(conf Config) net.Listener {

	// Load the certificate.
	cert, err := tls.LoadX509KeyPair(conf.ServerCertPath, conf.ServerKeyPath)
	if err != nil {
		slog.Error("Failed to load a key paire.", "error", err.Error())
		os.Exit(1)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		// THIS is what enables HTTP/2 negotiation
		NextProtos: []string{
			"h2", // HTTP/2
			"",   // no fallback
		},
	}

	ln, err := net.Listen("tcp", conf.Addr)
	if err != nil {
		slog.Error("Failed to listen.", "error", err)
		os.Exit(1)
	}

	// Wrap TCP with TLS.
	return tls.NewListener(ln, tlsConfig)

}

func constructListener(conf Config) net.Listener {

	ln, err := net.Listen("tcp", conf.Addr)
	if err != nil {
		slog.Error("Failed to listen.", "error", err)
		os.Exit(1)
	}

	return ln
}

type Config struct {
	RootDirPath    string
	Addr           string
	Home           string
	HttpOnly       bool
	ServerCertPath string
	ServerKeyPath  string
	NoCgroups      bool
}

// Parse input arguments and construct configuration from them.
func parseInputArguments() Config {

	rootDirPath := flag.String("rootDirPath", "./pages", "A directory from where the files are served.")
	addr := flag.String("address", ":8443", "An address <address>:<port> on which the server listens.")
	home := flag.String("home", "/home.html", "A home page to which GET '/' request is redirected to.")
	httpOnly := flag.Bool("http_only", false, "Use HTTP connection only.")
	serverCertPath := flag.String("server_cert", "./cert/server.crt", "Path to servers certificat")
	serverKeyPath := flag.String("server_key", "./cert/server.key", "Path to servers private key")
	// Only use in a container.
	noCgroups := flag.Bool("no_cgroups", false, "Do not use cgroups. Should only be used in a container with already limited use of resources.")

	flag.Parse()

	return Config{
		RootDirPath:    *rootDirPath,
		Addr:           *addr,
		Home:           *home,
		HttpOnly:       *httpOnly,
		ServerCertPath: *serverCertPath,
		ServerKeyPath:  *serverKeyPath,
		NoCgroups:      *noCgroups,
	}
}

func main() {

	// Parse input arguments.

	conf := parseInputArguments()

	slog.Info("Starting ...", "serving_files_from", conf.RootDirPath)

	var allowedPaths = make(map[string]*FileWrap)

	// The file descriptors opened below are read-only and are reclaimed by OS when the program exits.

	// Get all the pages / resources that can be served.
	err := filepath.WalkDir(conf.RootDirPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !d.IsDir() {

			f, err := os.Open(path)
			if err != nil {
				return fmt.Errorf("Failed to open a file: %w", err)
			}

			ipath := "/" + strings.Join(strings.Split(path, "/")[1:], "/")
			allowedPaths[ipath] = Wrap(f)

		}

		return nil
	})
	if err != nil {
		slog.Error("Walking rootDirPath.", "error", err)
		os.Exit(1)
	}

	for fpath := range allowedPaths {
		slog.Info("Serving file.", "path", fpath)
	}

	if conf.NoCgroups {
		slog.Warn("no_crgoups enabled. CPU and memory usage were not limited.")
	} else {
		// Limit to a single cpu and 512 bytes of memory.
		if err := limit_memory_and_cpu(1, 512); err != nil {
			slog.Error("Failed to limit memory and CPU.", "error", err.Error())
			os.Exit(1)
		}
	}

	// Start serving.

	mux := http.NewServeMux()

	server := &http.Server{
		Addr:    conf.Addr,
		Handler: mux,
	}

	// TODO: Server should handle the path instead of doing it by hand in ServerOnly.
	mux.HandleFunc("GET /", ServeOnly(allowedPaths, conf.Home))

	// Limit to HTTP/2.
	server.Protocols = new(http.Protocols)
	if conf.HttpOnly {
		server.Protocols.SetHTTP1(true)
		server.Protocols.SetHTTP2(false)
		server.Protocols.SetUnencryptedHTTP2(true)
	} else {
		server.Protocols.SetHTTP1(false)
		server.Protocols.SetHTTP2(true)
		server.Protocols.SetUnencryptedHTTP2(false)
	}

	// Construct TLS listener.
	var listener net.Listener
	if conf.HttpOnly {
		slog.Warn("Exposing HTTP only connection!")
		listener = constructListener(conf)
	} else {
		listener = constructTLSListener(conf)
	}

	// Restrict systemcalls that we do not need.
	allowedSysCalls := []string{
		"write", "epoll_ctl", "accept4", "epoll_pwait", "futex", "read",
		"getsockname", "getrandom", "lseek", "rt_sigprocmask", "tgkill",
		"rt_sigreturn", "rt_sigaction", "close",
		"clone3", "mmap", "mprotect", "set_robust_list", "rseq", "nanosleep",
		"munmap", "sigaltstack", "exit_group"}
	if err = whiteList(allowedSysCalls); err != nil {
		slog.Error("Failed seting seccomp.", "error", err)
		os.Exit(1)
	}

	// Shut down gracefully on SIGINT/SIGTERM, giving in-flight requests time
	// to finish instead of dropping them.
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh

		slog.Info("Shutting down ...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			slog.Error("Failed to shut down gracefully.", "error", err)
		}
	}()

	slog.Info("Listening ...", "on_address", server.Addr)

	// Server loop.
	err = server.Serve(listener)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("Failed to start the server.", "err", err)
		os.Exit(1)
	}
}
