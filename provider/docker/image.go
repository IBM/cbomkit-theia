package docker

type ScannableImage struct {
	Filesystem Filesystem
	DockerfilePath string
}

type Filesystem struct {
	Path string
}