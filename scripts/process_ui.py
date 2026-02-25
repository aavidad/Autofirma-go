import re

filepath = 'cmd/autofirma/ui.go'
with open(filepath, 'r') as f:
    content = f.read()

# 1. Update imports
# Remove all lines matching `gioui.org`
content = re.sub(r'\t"gioui.org[^\n]*\n', '', content)
# Insert Fyne imports into the main block
content = content.replace('"github.com/digitorus/pdf"\n', '"github.com/digitorus/pdf"\n\t"fyne.io/fyne/v2"\n\t"fyne.io/fyne/v2/dialog"\n\tfwidget "fyne.io/fyne/v2/widget"\n')

# 2. Modify UI struct definition
# We will match the UI struct declaration and replace all `widget.*`, `*material.Theme` and `*app.Window`
# This requires a more programmatic approach to just strip everything we don't need, 
# but simply removing `widget.*` won't compile because it has no types.
def replace_ui_struct(match):
    struct_body = match.group(1)
    
    # Remove gioui-specific struct fields broadly to start, or change them to interface{}
    struct_body = re.sub(r'^\s*Theme\s+\*material\.Theme\n', '', struct_body, flags=re.MULTILINE)
    struct_body = re.sub(r'^\s*Window\s+\*app\.Window\n', '\tWindow fyne.Window\n\tApp fyne.App\n', struct_body, flags=re.MULTILINE)
    # Replace all widget.Clickable, widget.Bool, widget.List, widget.Editor with interface{} for now so it compiles, 
    # we'll use Fyne specific struct variables later, or drop them entirely since Fyne tracks state inside the objects.
    struct_body = re.sub(r'widget\.[A-Za-z]+', 'any', struct_body)
    
    return 'type UI struct {' + struct_body + '\n}'
    
content = re.sub(r'type UI struct \{([\s\S]*?)\n\}', replace_ui_struct, content, 1)

# 3. Modify NewUI signature
content = content.replace('func NewUI(w *app.Window)', 'func NewFyneUI(a fyne.App, w fyne.Window)')

# 4. Remove all Layout methods and helpers
# Find all functions `func (ui *UI) [lL]ayout...` and remove them
def strip_layout_funcs(text):
    out = []
    skip = False
    brace = 0
    for line in text.split('\n'):
        if re.match(r'^func \(ui \*UI\) [lL]ayout', line) or re.match(r'^func \(ui \*UI\) compose', line):
            skip = True
            brace = line.count('{') - line.count('}')
            continue
        if skip:
            brace += line.count('{') - line.count('}')
            if brace <= 0:
                skip = False
            continue
        out.append(line)
    return '\n'.join(out)

content = strip_layout_funcs(content)

# 5. Invalidate() -> Refresh()
content = content.replace('ui.Window.Invalidate()', 'ui.Refresh()')
content = content.replace('u.Window.Invalidate()', 'u.Refresh()')

# Append a dummy Refresh method
content += '\nfunc (ui *UI) Refresh() {\n\t// TODO: Refresh implementado por Fyne\n}\n'

with open(filepath, 'w') as f:
    f.write(content)

print("ui.go process complete")
