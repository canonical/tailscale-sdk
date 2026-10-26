package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

type interactivePrompter struct {
	reader       lineReader
	secretReader secretReader
	writer       io.Writer
}

type lineReader interface {
	ReadString(delim byte) (string, error)
}

// Prompter reads answers required by an interactive workflow.
type Prompter interface {
	// Confirm asks for a yes or no answer using the supplied default.
	Confirm(label string, defaultYes bool) (bool, error)

	// Input asks for a value using the supplied default for empty input.
	Input(label string, defaultValue string) (string, error)

	// Secret asks for a value without exposing it in terminal output.
	Secret(label string) (string, error)
}

type secretReader func() (string, error)

// Confirm asks for a yes or no answer using the supplied default.
func (p interactivePrompter) Confirm(
	label string,
	defaultYes bool,
) (bool, error) {
	suffix := " [Y/n]: "
	if !defaultYes {
		suffix = " [y/N]: "
	}
	for {
		fmt.Fprint(p.writer, label+suffix)
		answer, err := p.readLine()
		if err != nil {
			return false, err
		}
		switch strings.ToLower(answer) {
		case "":
			return defaultYes, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		default:
			fmt.Fprintln(p.writer, "Enter yes or no.")
		}
	}
}

// Input asks for a value using the supplied default for empty input.
func (p interactivePrompter) Input(
	label string,
	defaultValue string,
) (string, error) {
	for {
		if defaultValue == "" {
			fmt.Fprintf(p.writer, "%s: ", label)
		} else {
			fmt.Fprintf(p.writer, "%s [%s]: ", label, defaultValue)
		}
		value, err := p.readLine()
		if err != nil {
			return "", err
		}
		if value == "" {
			value = defaultValue
		}
		if value != "" {
			return value, nil
		}
		fmt.Fprintln(p.writer, "A value is required.")
	}
}

func newInteractivePrompter(
	in lineReader,
	out io.Writer,
	readSecret secretReader,
) interactivePrompter {
	return interactivePrompter{
		reader:       in,
		secretReader: readSecret,
		writer:       out,
	}
}

func (p interactivePrompter) readLine() (string, error) {
	line, err := p.reader.ReadString('\n')
	if err == io.EOF && len(line) == 0 {
		return "", fmt.Errorf("input ended before setup completed")
	} else if err != nil && len(line) == 0 {
		return "", fmt.Errorf("read input: %w", err)
	}
	return strings.TrimSpace(line), nil
}

func readSecret() (string, error) {
	value, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", fmt.Errorf("read secret: %w", err)
	}
	return string(value), nil
}

// Secret asks for a value without exposing it in terminal output.
func (p interactivePrompter) Secret(label string) (string, error) {
	for {
		fmt.Fprintf(p.writer, "%s: ", label)
		value, err := p.secretReader()
		fmt.Fprintln(p.writer)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", label, err)
		}
		value = strings.TrimSpace(value)
		if value != "" {
			return value, nil
		}
		fmt.Fprintln(p.writer, "A value is required.")
	}
}
