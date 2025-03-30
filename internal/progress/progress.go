// Package progress provides utilities for displaying progress information to the user.
package progress

import (
	"fmt"
	"sync"
	"time"
)

// Bar represents a console progress bar.
type Bar struct {
	// total is the total number of steps in the progress bar.
	total int

	// current is the current step in the progress.
	current int

	// width is the width of the progress bar in characters.
	width int

	// description is the text describing the current operation.
	description string

	// mu is a mutex to protect updates to the progress bar.
	mu sync.Mutex

	// startTime is when the progress bar was created.
	startTime time.Time
}

// NewBar creates a new progress bar with the given total steps.
func NewBar(total int) *Bar {
	return &Bar{
		total:     total,
		current:   0,
		width:     40,
		startTime: time.Now(),
	}
}

// Update updates the progress bar with a new current value and description.
func (b *Bar) Update(current int, description string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.current = current
	if b.current > b.total {
		b.current = b.total
	}

	b.description = description
	b.draw()
}

// Increment increases the current value by one and updates the description.
func (b *Bar) Increment(description string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.current++
	if b.current > b.total {
		b.current = b.total
	}

	b.description = description
	b.draw()
}

// Complete marks the progress bar as complete.
func (b *Bar) Complete(description string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.current = b.total
	b.description = description
	b.draw()
	fmt.Println() // Add a newline after completing
}

// draw renders the progress bar to the console.
func (b *Bar) draw() {
	percent := float64(b.current) / float64(b.total) * 100
	filled := int(float64(b.width) * (float64(b.current) / float64(b.total)))

	// Create the progress bar string
	bar := "["
	for i := 0; i < b.width; i++ {
		if i < filled {
			bar += "="
		} else {
			bar += " "
		}
	}
	bar += "]"

	// Calculate elapsed time
	elapsed := time.Since(b.startTime).Round(time.Second)

	// Print the progress bar with carriage return to overwrite the previous line
	fmt.Printf("\r%s %3.0f%% %s (%d/%d) [%s elapsed]",
		bar, percent, b.description, b.current, b.total, elapsed)
}
