// Package image builds and tracks the base VHDX every project VM is a
// differencing child of.
package image

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"windevvm/internal/cloudinit"
	"windevvm/internal/config"
	"windevvm/internal/diskimg"
	"windevvm/internal/hyperv"
	"windevvm/internal/seed"
)

// Base describes a built base image.
type Base struct {
	Path    string    `json:"path"`
	Created time.Time `json:"created"`
	Release string    `json:"release"`
	Tools   []string  `json:"tools"`
}

// Dir is where images live.
func Dir(cfg config.Global) string { return filepath.Join(cfg.Storage(), "images") }

func currentPath(cfg config.Global) string { return filepath.Join(Dir(cfg), "current.json") }

// ErrNoImage means no base image has been built yet.
var ErrNoImage = errors.New("no base image yet; build one with: windevvm image build")

// readCurrent reads current.json, whether or not the image still exists.
func readCurrent(cfg config.Global) (Base, error) {
	var b Base
	data, err := os.ReadFile(currentPath(cfg))
	if errors.Is(err, fs.ErrNotExist) {
		return b, ErrNoImage
	}
	if err != nil {
		return b, err
	}
	err = json.Unmarshal(data, &b)
	return b, err
}

// CurrentPath returns the path of the current base image as recorded,
// whether or not the file still exists.
func CurrentPath(cfg config.Global) (string, error) {
	b, err := readCurrent(cfg)
	return b.Path, err
}

// Current returns the base image new VMs are created from.
func Current(cfg config.Global) (Base, error) {
	b, err := readCurrent(cfg)
	if err != nil {
		return b, err
	}
	if _, err := os.Stat(b.Path); err != nil {
		return b, fmt.Errorf("base image %s is missing; rebuild with: windevvm image build", b.Path)
	}
	return b, nil
}

// List returns all base image files.
func List(cfg config.Global) ([]string, error) {
	return filepath.Glob(filepath.Join(Dir(cfg), "base-*.vhdx"))
}

// Builder builds a new base image.
type Builder struct {
	Cfg config.Global
	HV  *hyperv.Client
	Out io.Writer
	// HTTP downloads the cloud image. Defaults to http.DefaultClient.
	HTTP *http.Client
}

func (b *Builder) say(format string, a ...any) { fmt.Fprintf(b.Out, format+"\n", a...) }

func (b *Builder) cloudImageURL() string {
	return fmt.Sprintf("https://cloud-images.ubuntu.com/%s/current/", b.Cfg.Image.Release)
}

func (b *Builder) cloudImageName() string {
	return b.Cfg.Image.Release + "-server-cloudimg-amd64.img"
}

// Build creates a new base image and makes it current.
func (b *Builder) Build(ctx context.Context) (Base, error) {
	dir := Dir(b.Cfg)
	if err := os.MkdirAll(filepath.Join(dir, "cache"), 0o755); err != nil {
		return Base{}, err
	}
	ok, err := b.HV.SwitchExists(ctx, hyperv.DefaultSwitch)
	if err != nil {
		return Base{}, err
	}
	if !ok {
		return Base{}, fmt.Errorf("Hyper-V's %q is missing; the base image build needs it for internet access", hyperv.DefaultSwitch)
	}

	qcow, err := b.download(ctx)
	if err != nil {
		return Base{}, err
	}

	stamp := time.Now().Format("20060102-150405")
	vhd := filepath.Join(dir, "build-"+stamp+".vhd")
	vhdx := filepath.Join(dir, "base-"+stamp+".vhdx")
	logPath := filepath.Join(dir, "base-"+stamp+".log")
	isoPath := filepath.Join(dir, "build-"+stamp+".iso")
	vmName := "wdvm-build-" + stamp
	vmDir := filepath.Join(dir, "build-"+stamp)
	success := false
	defer func() {
		os.Remove(vhd)
		os.Remove(isoPath)
		if !success {
			b.HV.Remove(context.Background(), vmName)
			os.Remove(vhdx)
		}
		os.RemoveAll(vmDir)
	}()

	b.say("Converting the cloud image to a Hyper-V disk...")
	if err := diskimg.QcowToVHD(qcow, vhd); err != nil {
		return Base{}, err
	}
	if err := b.HV.ConvertToDynamicVHDX(ctx, vhd, vhdx); err != nil {
		return Base{}, err
	}
	os.Remove(vhd)
	if err := b.HV.ResizeVHD(ctx, vhdx, int64(b.Cfg.Image.Disk)); err != nil {
		return Base{}, err
	}

	files, err := cloudinit.BaseSeed(cloudinit.BaseSpec{Packages: b.Cfg.Image.Packages, Tools: b.Cfg.Image.Tools, NpmGlobal: b.Cfg.Image.NpmGlobal})
	if err != nil {
		return Base{}, err
	}
	if err := seed.WriteISO(isoPath, files); err != nil {
		return Base{}, err
	}

	pipe := `\\.\pipe\` + vmName
	b.say("Booting a build VM to install packages and toolchains (about 5-15 minutes)...")
	if err := b.HV.CreateVM(ctx, hyperv.CreateSpec{
		Name: vmName, Dir: vmDir, Disk: vhdx, SeedISO: isoPath,
		Switch: hyperv.DefaultSwitch, ComPipe: pipe, Memory: 4 << 30,
	}); err != nil {
		return Base{}, err
	}
	if _, err := b.HV.ApplyCaps(ctx, vmName, hyperv.Caps{
		CPUs: 4, CPUMaxPercent: 100, CPUWeight: 100,
		MemoryStartup: 4 << 30, MemoryMin: 1 << 30, MemoryMax: 6 << 30,
	}); err != nil {
		return Base{}, err
	}
	if err := b.HV.Start(ctx, vmName); err != nil {
		return Base{}, err
	}
	if err := b.watch(ctx, vmName, pipe, logPath); err != nil {
		return Base{}, err
	}
	if err := b.HV.Remove(ctx, vmName); err != nil {
		return Base{}, err
	}
	b.say("Compacting the disk...")
	if err := b.HV.OptimizeVHD(ctx, vhdx); err != nil {
		b.say("  (skipped: %v)", err)
	}
	// Differencing children depend on the parent never changing.
	if err := os.Chmod(vhdx, 0o444); err != nil {
		return Base{}, err
	}

	base := Base{Path: vhdx, Created: time.Now(), Release: b.Cfg.Image.Release, Tools: b.Cfg.Image.Tools}
	data, _ := json.MarshalIndent(base, "", "  ")
	if err := os.WriteFile(currentPath(b.Cfg), data, 0o644); err != nil {
		return Base{}, err
	}
	success = true
	return base, nil
}

// watch streams the build VM's serial console to a log, echoing progress
// markers, until the VM powers off. It fails unless the success marker appeared.
func (b *Builder) watch(ctx context.Context, vmName, pipe, logPath string) error {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Minute)
	defer cancel()
	logf, err := os.Create(logPath)
	if err != nil {
		return err
	}
	defer logf.Close()

	con, err := hyperv.OpenConsole(ctx, pipe)
	if err != nil {
		return fmt.Errorf("open build console: %w", err)
	}
	// Closing the console unblocks the reader if we give up early.
	go func() { <-ctx.Done(); con.Close() }()

	var okSeen, failed bool
	var failLine string
	sc := bufio.NewScanner(io.TeeReader(con, logf))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.Contains(line, cloudinit.BuildOK):
			okSeen = true
		case strings.Contains(line, cloudinit.BuildFailed):
			failed, failLine = true, line
		case strings.HasPrefix(line, cloudinit.Progress):
			b.say("  %s", strings.TrimPrefix(line, cloudinit.Progress))
		}
		if failed {
			break
		}
	}
	con.Close()

	if failed {
		b.HV.TurnOff(context.Background(), vmName)
		return fmt.Errorf("base image build failed (%s); see %s", failLine, logPath)
	}
	if ctx.Err() != nil {
		b.HV.TurnOff(context.Background(), vmName)
		return fmt.Errorf("base image build timed out; see %s", logPath)
	}
	// The console closes at power-off; make sure the VM really is off.
	for i := 0; i < 60; i++ {
		v, ok, err := b.HV.GetVM(ctx, vmName)
		if err != nil {
			return err
		}
		if !ok || !v.Running() {
			break
		}
		time.Sleep(time.Second)
	}
	if !okSeen {
		return fmt.Errorf("base image build ended without finishing; see %s", logPath)
	}
	return nil
}

// download fetches the cloud image into the cache, verifying it against the
// published SHA256SUMS, and reuses a cached copy that still matches.
func (b *Builder) download(ctx context.Context) (string, error) {
	client := b.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	name := b.cloudImageName()
	sums, err := fetch(ctx, client, b.cloudImageURL()+"SHA256SUMS")
	if err != nil {
		return "", fmt.Errorf("fetch checksums: %w", err)
	}
	want, err := findSum(string(sums), name)
	if err != nil {
		return "", err
	}
	path := filepath.Join(Dir(b.Cfg), "cache", name)
	if got, err := fileSHA256(path); err == nil && got == want {
		b.say("Using the cached Ubuntu %s cloud image.", b.Cfg.Image.Release)
		return path, nil
	}

	b.say("Downloading the Ubuntu %s cloud image (about 600MB)...", b.Cfg.Image.Release)
	req, err := http.NewRequestWithContext(ctx, "GET", b.cloudImageURL()+name, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("download %s: %s", name, resp.Status)
	}
	tmp := path + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), resp.Body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return "", err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		os.Remove(tmp)
		return "", fmt.Errorf("checksum mismatch for %s: got %s, want %s", name, got, want)
	}
	return path, os.Rename(tmp, path)
}

func fetch(ctx context.Context, c *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

func findSum(sums, name string) (string, error) {
	for _, line := range strings.Split(sums, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name && len(f[0]) == 64 {
			return strings.ToLower(f[0]), nil
		}
	}
	return "", fmt.Errorf("no checksum published for %s", name)
}

func fileSHA256(path string) (string, error) {
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
