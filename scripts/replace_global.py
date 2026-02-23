import glob
import re
import os

gui_files = glob.glob('cmd/gui/*.go')

for filepath in gui_files:
    with open(filepath, 'r') as f:
        content = f.read()

    # Invalidate -> Refresh
    content = content.replace('ui.Window.Invalidate()', 'ui.Refresh()')
    content = content.replace('s.ui.Window.Invalidate()', 's.ui.Refresh()')

    # Remove app.Window and gioui references in main
    if 'main.go' in filepath:
        content = content.replace('w := new(app.Window)', 'a := app.New()\nw := a.NewWindow("AutoFirma")')
        content = content.replace('w.Option(app.Title("AutoFirma - Diputación de Granada"), app.Size(unit.Dp(800), unit.Dp(600)))', 'w.Resize(fyne.NewSize(1100, 750))')
        content = content.replace('ui := NewUI(w)', 'ui := NewFyneUI(a, w)')
        content = content.replace('app.Main()', 'w.ShowAndRun()')
        content = content.replace('ui.Layout(gtx)', '')
        content = content.replace('func loop(w *app.Window, ui *UI) error', 'func loop(w fyne.Window, ui *UI) error')
        # Limpiar frame loops
        content = re.sub(r'for \{\n\t\te := w\.Event\(\)\n[\s\S]*?\}', '', content)
        content = content.replace('.(type)', '') # just in case
        
    if 'ui.go' in filepath:
        content = re.sub(r'widget\.[A-Za-z]+', 'any', content)
        content = content.replace('layout.Context', 'any')
        content = content.replace('app.Window', 'fyne.Window')
        
    with open(filepath, 'w') as f:
        f.write(content)

print("Global replace OK")
