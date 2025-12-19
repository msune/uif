package main

import (
	"bytes"
	_ "embed"
	"errors"
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"
	libebpf "github.com/cilium/ebpf"
	libebpf_link "github.com/cilium/ebpf/link"
)

const (
	basePinDir      = "/sys/fs/bpf/uif/"
)

//go:embed untagged.o
var bpfProgram []byte

func loadAndAttach(ifName string, dir string, ifIndex int32) error {
	objs := struct {
		Prog *libebpf.Program `ebpf:"prog"`
	}{}

	err := os.MkdirAll(basePinDir, 0755)
	if err != nil {
		log.Fatalf("failed to create directory '%s': %v", basePinDir, err)
	}

	spec, err := libebpf.LoadCollectionSpecFromReader(
		bytes.NewReader(bpfProgram),
	)
	if err != nil {
		log.Printf("ERROR: loading eBPF spec for program: %v", err)
		return err
	}

	collOpts := libebpf.CollectionOptions {
		Maps: libebpf.MapOptions {
			PinPath: basePinDir,
		},
		Programs: libebpf.ProgramOptions{
			LogLevel: libebpf.LogLevelInstruction | libebpf.LogLevelBranch | libebpf.LogLevelStats,
		},
	}

	coll, err := libebpf.NewCollectionWithOptions(spec, collOpts)

	var ve *libebpf.VerifierError
	if errors.As(err, &ve) {
		log.Printf("Verifier error:\n%+v", ve)
	}

	if err != nil {
		log.Printf("ERROR: creating eBPF collection for program: %v", err)
		return err
	}

	funcName := "uif_" + dir
	objs.Prog = coll.Programs[funcName]
	if objs.Prog == nil {
		log.Printf("ERROR: trying to find function '%s' for program", funcName)
		return err
	}

	attachType := libebpf.AttachTCXIngress
	if dir != "ingress" {
		attachType = libebpf.AttachTCXEgress
	}
	opts := libebpf_link.TCXOptions{
		Program:   objs.Prog,
		Attach:    attachType,
		Interface: int(ifIndex),
	}

	link, err := libebpf_link.AttachTCX(opts)
	if err != nil {
		log.Printf("ERROR: loading eBPF program '%s' on iface %s: %v", ifName, dir, err)
		return err
	}

 	pinPath := basePinDir + ifName + "-" + dir

	// If pinPath exists it's from an interface that existed
	// with the same name. Remove it and cleanup refs.
	if err := os.Remove(pinPath); err != nil && !os.IsNotExist(err) {
		log.Printf("ERROR: unable to remove pinPaht '%s' of iface %s (old iface): %v", pinPath, ifName, err)
		return err
	}

	err = link.Pin(pinPath)
	if err != nil {
		log.Printf("ERROR: unable to pin TCX program on iface '%s' to path '%s': %v", ifName, pinPath, err)

		link.Close()
		return err
	}

	return nil
}

func create(cmd *cobra.Command, args []string) {
	name := args[0]

	nl, err := netlink.LinkByName(name)
	if err != nil {
		log.Fatalf("ERROR: interface '%s' not found. %v", name, err)
	}

	// Create VLAN 0 subinterface
	vlan0 := &netlink.Vlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:        name + ".ut",
			ParentIndex: nl.Attrs().Index,
		},
		VlanId: 0,
	}

	if err := netlink.LinkAdd(vlan0); err != nil {
		log.Fatalf("failed to add vlan: %v", err)
	}

	// Attach BPF Ingress program
	ifIndex := int32(nl.Attrs().Index)
	err = loadAndAttach(name, "ingress", ifIndex)
	if err != nil {
		log.Fatalf("%v", err)
	}

	// Egress program
	err = loadAndAttach(name, "egress", ifIndex)
	if err != nil {
		log.Fatalf("%v", err)
	}
}

func main() {
	root := &cobra.Command{
		Use:   "uif",
		Short: "Manage untagged interfaces",
	}

	createCmd := cobra.Command{
		Use:   "create <iface>",
		Short: "Create an untagged interface from iface ('iface.ut')",
		Args:  cobra.ExactArgs(1),
		Run:   create,
	}

	root.AddCommand(&createCmd)

	if err := root.Execute(); err != nil {
		log.Fatalf("error: %v", err)
	}
}
