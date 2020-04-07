package matchers

type RenderingContext struct {
	templates []string
	data      map[string]string
}

func (r RenderingContext) WithData(data map[string]string) RenderingContext {
	r.data = data
	return r
}

func NewRenderingContext(templates ...string) RenderingContext {
	return RenderingContext{templates, nil}
}
