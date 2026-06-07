package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/landlock-lsm/go-landlock/landlock"
	libseccomp "github.com/seccomp/libseccomp-golang"
)

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

	// TODO: The user ID should be retrieved from environment.
	cgroupRoot := "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/"
	cgroupName := "ajda.service"
	cgroupPath := filepath.Join(cgroupRoot, cgroupName)

	// Create cgroup.
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
		return fmt.Errorf("Failed to add proces to the group: %w", err)
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

// TODO: Test that panic from a Gorutine crashes the entite program.

// Serve only allowed paths.
func ServeOnly(rootDir *os.Root, availableFiles map[string]bool, home string) func(http.ResponseWriter, *http.Request) {

	return func(w http.ResponseWriter, req *http.Request) {

		id, err := randomHex(3)
		if err != nil {
			slog.Error(err.Error())
			os.Exit(1)
		}

		// Setup request specific logger.
		log := slog.With("req_id", id)

		path := req.URL.Path

		log.Info("Received request.", "path", path, "from", req.RemoteAddr)

		// Redirecto to home page if "/" path provided.
		if path == "/" {
			slog.Info("Redirecting.", "to", home)
			http.Redirect(w, req, home, http.StatusFound)
			return
		}

		// Check if the requested path is allowed.
		if _, ok := availableFiles[path]; !ok {
			log.Warn("File not available.", "path", path)
			CannotBeServed(w)
			return
		}

		// TODO: Check that the path is of the right form. Deos Go's library already handles that?
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

		f, err := rootDir.Open(path[1:])
		if err != nil {
			log.Error("File could not be opened.", "error", err)
			CannotBeServed(w)
			return
		}
		defer f.Close()
		_, err = io.Copy(w, f)
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
	NoLandlock     bool
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
	noLandlock := flag.Bool("no_landlock", false, "Do not use landlock. Should only be used in a container with already limited file system access.")

	flag.Parse()

	return Config{
		RootDirPath:    *rootDirPath,
		Addr:           *addr,
		Home:           *home,
		HttpOnly:       *httpOnly,
		ServerCertPath: *serverCertPath,
		ServerKeyPath:  *serverKeyPath,
		NoCgroups:      *noCgroups,
		NoLandlock:     *noLandlock,
	}
}

func main() {

	// Parse input arguments.

	conf := parseInputArguments()

	slog.Info("Starting ...")

	var allowedPaths = make(map[string]bool)

	// Get all the pages / resources that can be served.
	err := filepath.WalkDir(conf.RootDirPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !d.IsDir() {

			ipath := "/" + strings.Join(strings.Split(path, "/")[1:], "/")
			allowedPaths[ipath] = true

		}

		return nil
	})
	if err != nil {
		slog.Error("Walking rootDirPath.", "error", err)
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

	absRootDirPath, err := filepath.Abs(conf.RootDirPath)
	if err != nil {
		slog.Error("Failed to convert to absolute path.", "err", err)
	}

	rootDir, err := os.OpenRoot(conf.RootDirPath)
	if err != nil {
		slog.Error("Failed to open the root directory using os.OpenRoot.", "error", err.Error())
		os.Exit(1)
	}

	mux := http.NewServeMux()

	server := &http.Server{
		Addr:    conf.Addr,
		Handler: mux,
	}

	mux.HandleFunc("GET /", ServeOnly(rootDir, allowedPaths, conf.Home))

	// Limit to HTTP/2.
	server.Protocols = new(http.Protocols)
	if conf.HttpOnly {
		server.Protocols.SetHTTP1(true) // TODO: Should work only with HTTP/2.
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

	if conf.NoLandlock {
		slog.Warn("no_landlock enabled. Access to files is not restricted to the root directory.")
	} else {
		// Only allow reading from the root dir.
		slog.Info("Restricting file access.", "to_path", absRootDirPath)
		err = landlock.V8.RestrictPaths(
			landlock.RODirs(absRootDirPath),
		)
		if err != nil {
			slog.Error("Failed to restrict file access to root directory.", "error", err)
			os.Exit(1)
		}
	}

	// Restrict systemcalls that we do not need.
	allowedSysCalls := []string{
		"write", "epoll_ctl", "close", "exit_group", "accept4",
		"nanosleep", "epoll_pwait", "futex", "sched_yield", "read",
		"mmap", "getsockname", "setsockopt", "prctl", "getrandom",
		"lseek", "openat", "rt_sigprocmask", "getpid", "tgkill",
		"gettid", "fsync", "rt_sigreturn", "rt_sigaction"}
	if err = whiteList(allowedSysCalls); err != nil {
		slog.Error("Failed seting seccomp.", "error", err)
		os.Exit(1)
	}

	slog.Info("Listening ...", "on_address", server.Addr)

	// Server lop.
	err = server.Serve(listener)
	if err != nil {
		slog.Error("Failed to start the server.", "err", err)
		os.Exit(1)
	}
}
