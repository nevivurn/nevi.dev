import Reveal from "reveal.js/dist/reveal.esm.js"
import Highlight from "reveal.js/plugin/markdown/markdown.esm.js"
import Markdown from "reveal.js/plugin/highlight/highlight.esm.js"
import Notes from "reveal.js/plugin/notes/notes.esm.js"

const deck = new Reveal({
  embedded: true,
  plugins: [Markdown, Highlight, Notes],
})
deck.initialize()
