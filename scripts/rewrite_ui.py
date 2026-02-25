import re

with open('cmd/autofirma/ui.go', 'r') as f:
    lines = f.readlines()

# Cambiar el inicio de ui.go para quitar imports gioui
content = "".join(lines)
content = re.sub(r'import \([\s\S]*?\n\)\n', '''import (
\t"autofirma/pkg/applog"
\t"autofirma/pkg/browser"
\t"autofirma/pkg/certstore"
\t"autofirma/pkg/config"
\t"autofirma/pkg/diag"
\t"autofirma/pkg/protocol"
\t"autofirma/pkg/update"

\t"bytes"
\t"crypto/x509"
\t"encoding/json"
\t"fmt"
\t"image"
\t"log"
\t"math"
\t"os"
\t"os/exec"
\t"path/filepath"
\t"runtime"
\t"strings"
\t"sync"
\t"time"
\t"net/url"

\t"github.com/digitorus/pdf"

\t"fyne.io/fyne/v2"
\t"fyne.io/fyne/v2/dialog"
\t"fyne.io/fyne/v2/widget"
)
''', content, 1)

# Eliminar todos los métodos que empiezan por layout* o Layout*
# Esta regex busca func (ui *UI) layoutAlgo y se salta su contenido hasta el fin de llave
# Requiere parsear un poco
out_lines = []
skip = False
brace_count = 0
for line in content.split('\n'):
    if re.match(r'^func \(ui \*UI\) [lL]ayout', line):
        skip = True
        brace_count = line.count('{') - line.count('}')
        continue
    
    if skip:
        brace_count += line.count('{') - line.count('}')
        if brace_count <= 0:
            skip = False
        continue
    
    out_lines.append(line)

final_content = '\n'.join(out_lines)

# Reemplazar ui.Window.Invalidate() por ui.Refresh()
final_content = final_content.replace('ui.Window.Invalidate()', 'ui.Refresh()')
final_content = final_content.replace('w *app.Window', 'w fyne.Window')

with open('cmd/autofirma/ui.go', 'w') as f:
    f.write(final_content)

print("ui.go rewrite OK")
