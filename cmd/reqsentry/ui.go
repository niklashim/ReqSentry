package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/niklashim/ReqSentry/internal/config"
	"gopkg.in/yaml.v3"
)

func mappingValue(n *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}
func setMapping(n *yaml.Node, key string, value *yaml.Node) {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			n.Content[i+1] = value
			return
		}
	}
	n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, value)
}

func toggleUI(path string, enabled bool, stdout, stderr io.Writer) int {
	if err := saveUI(path, enabled); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	action := "disabled"
	if enabled {
		action = "enabled"
	}
	fmt.Fprintf(stdout, "UI %s in %s. Restart ReqSentry to apply; log monitoring and notifications remain configured.\n", action, terminalText(path, 512))
	return 0
}
func saveUI(path string, enabled bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("UI configuration must be a regular file (symlinks are not rewritten)")
	}
	original, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(original, &doc); err != nil {
		return err
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("configuration must be a YAML mapping")
	}
	root := doc.Content[0]
	web := mappingValue(root, "web")
	if web == nil {
		web = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		setMapping(root, "web", web)
	}
	if web.Kind != yaml.MappingNode {
		return fmt.Errorf("web must be a YAML mapping; expand aliases before changing it")
	}
	value := "false"
	if enabled {
		value = "true"
	}
	toggle := mappingValue(web, "enabled")
	if toggle == nil {
		toggle = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool"}
		setMapping(web, "enabled", toggle)
	}
	toggle.Value = value
	toggle.Tag = "!!bool"
	// First-time enablement is useful through localhost/SSH while remaining private.
	if enabled && mappingValue(web, "allowed_ips") == nil {
		setMapping(web, "allowed_ips", &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{{Kind: yaml.ScalarNode, Tag: "!!str", Value: "127.0.0.1"}, {Kind: yaml.ScalarNode, Tag: "!!str", Value: "::1"}}})
	}
	var buffer bytes.Buffer
	enc := yaml.NewEncoder(&buffer)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".reqsentry-config-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		if err := tmp.Chown(int(stat.Uid), int(stat.Gid)); err != nil {
			return err
		}
	}
	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		return err
	}
	if _, err := tmp.Write(buffer.Bytes()); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if _, err := config.Load(tmp.Name()); err != nil {
		return fmt.Errorf("UI setting would produce invalid configuration: %w", err)
	}
	current, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, original) {
		return fmt.Errorf("configuration changed concurrently; retry UI command")
	}
	return os.Rename(tmp.Name(), path)
}
