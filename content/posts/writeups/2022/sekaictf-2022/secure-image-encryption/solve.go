package main

import (
	"image"
	"image/png"
	"os"
)

const size = 256

func openImg(name string) image.Image {
	f, err := os.Open(name)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	img, err := png.Decode(f)
	if err != nil {
		panic(err)
	}

	return img
}

func main() {
	horiz := openImg(os.Args[1]).(*image.Gray)
	vert := openImg(os.Args[2]).(*image.Gray)

	idx := make([][]image.Point, size)
	for x := 0; x < size; x++ {
		idx[x] = make([]image.Point, size)
		for y := 0; y < size; y++ {
			rx := vert.GrayAt(x, y).Y
			ry := horiz.GrayAt(x, y).Y
			idx[x][y] = image.Pt(int(rx), int(ry))
		}
	}

	enc := openImg(os.Args[3]).(*image.Paletted)
	dec := image.NewPaletted(enc.Bounds(), enc.Palette)

	for x := 0; x < size; x++ {
		for y := 0; y < size; y++ {
			tg := idx[x][y]
			dec.SetColorIndex(tg.X, tg.Y, enc.ColorIndexAt(x, y))
		}
	}

	png.Encode(os.Stdout, dec)
}
