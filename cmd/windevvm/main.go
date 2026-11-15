// Command windevvm runs dev projects in isolated Hyper-V VMs.
package main

import (
	"fmt"
	"os"
)

const usage = `windevvm: isolated dev VMs for Windows

Usage:
  windevvm secret set NAME [--preset P | --hosts h1,h2] [--in header,url,body] [--from-env VAR]
  windevvm secret ls
  windevvm secret rm NAME
  windevvm ca init        create the local CA (if missing) and print its path
  windevvm dev-proxy      run the injecting proxy on this machine, for trying it out

Run "windevvm <command> -h" for a command's flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "secret":
		err = cmdSecret(os.Args[2:])
	case "ca":
		err = cmdCA(os.Args[2:])
	case "dev-proxy":
		err = cmdDevProxy(os.Args[2:])
	case "help", "-h", "--help":
		fmt.Print(usage)
		return
	default:
		err = fmt.Errorf("unknown command %q\n\n%s", os.Args[1], usage)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "windevvm:", err)
		os.Exit(1)
	}
}
