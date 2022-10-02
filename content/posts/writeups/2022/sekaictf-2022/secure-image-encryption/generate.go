package main

import (
	"image"
	"image/color"
	"image/png"
	"os"
)

const size = 256

func main() {
	fh, err := os.Create("horiz.png")
	if err != nil {
		panic(err)
	}
	defer fh.Close()

	fv, err := os.Create("vert.png")
	if err != nil {
		panic(err)
	}
	defer fv.Close()

	img := image.NewGray(image.Rect(0, 0, size, size))

	for x := 0; x < size; x++ {
		for y := 0; y < size; y++ {
			img.SetGray(x, y, color.Gray{uint8(y)})
		}
	}
	if err := png.Encode(fh, img); err != nil {
		panic(err)
	}

	for x := 0; x < size; x++ {
		for y := 0; y < size; y++ {
			img.SetGray(x, y, color.Gray{uint8(x)})
		}
	}
	if err := png.Encode(fv, img); err != nil {
		panic(err)
	}
}
