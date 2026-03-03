import tkinter as tk
from tkinter import filedialog, messagebox, ttk, simpledialog
import pandas as pd
import os
from datetime import datetime
from reporter_html import generar_reporte_html

class FirewallSegmentacionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("RulesAudit v1.0 - Firewall Segmentation Analyzer")
        self.root.geometry("1400x800")
        
        self.configure_dark_mode()
        
        self.modo = "CDE → CNTO"  
        self.CDE_PREFIXES = []
        self.CNTO_PREFIXES = []
        self.NOPCI_PREFIXES = []  
        self.df = None
        self.ultimos_resultados = []
        
        self.setup_ui()
        self.animate_title()

    def configure_dark_mode(self):
        self.colors = {
            'bg': '#0a0e12',
            'fg': '#00ff9d',
            'secondary_bg': '#1a1e24',
            'secondary_fg': '#e0e0e0',
            'accent': '#00ff9d',
            'accent2': '#ff0066',
            'terminal_green': '#00ff9d',
            'terminal_amber': '#ffb86b',
            'terminal_purple': '#bd93f9',
            'terminal_blue': '#5fa4e6', 
            'table_bg': '#0f1117',
            'table_header': '#1e2130',
            'table_row_even': '#161a24',
            'table_row_odd': '#1e2430',
            'grid_line_primary': '#2d3648',
            'grid_line_secondary': '#3e4a5e',
            'grid_line_accent': '#5f6b7f',
            'border_light': '#2a3344',
            'border_dark': '#0b0e14',
            'white': '#ffffff',
            'details_bg': '#1a1f2a',
            'details_accent': '#00ccff',
            'export_color': '#9d4edd'
        }
        
        self.root.configure(bg=self.colors['bg'])
        
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure('Treeview',
                       background=self.colors['table_bg'],
                       foreground=self.colors['secondary_fg'],
                       fieldbackground=self.colors['table_bg'],
                       borderwidth=0,
                       relief='flat',
                       font=('Segoe UI', 10))
        
        style.configure('Treeview.Heading',
                       background=self.colors['table_header'],
                       foreground=self.colors['accent'],
                       relief='raised',
                       borderwidth=2,
                       font=('Segoe UI', 11, 'bold'))
        
        style.map('Treeview.Heading',
                 background=[('active', self.colors['grid_line_accent'])],
                 foreground=[('active', 'black')])
        
        style.map('Treeview',
                 background=[('selected', self.colors['accent'])],
                 foreground=[('selected', 'black')])
        
        style.configure('Hacker.Vertical.TScrollbar',
                       background=self.colors['table_header'],
                       troughcolor=self.colors['bg'],
                       bordercolor=self.colors['grid_line_primary'],
                       arrowcolor=self.colors['accent'],
                       relief='flat')
        
        style.configure('Hacker.Horizontal.TScrollbar',
                       background=self.colors['table_header'],
                       troughcolor=self.colors['bg'],
                       bordercolor=self.colors['grid_line_primary'],
                       arrowcolor=self.colors['accent'],
                       relief='flat')
        
        style.configure('Hacker.TButton',
                       background=self.colors['secondary_bg'],
                       foreground=self.colors['accent'],
                       borderwidth=2,
                       focuscolor='none',
                       font=('Segoe UI', 10, 'bold'),
                       relief='raised')
        
        style.map('Hacker.TButton',
                 background=[('active', self.colors['accent'])],
                 foreground=[('active', 'black')],
                 relief=[('pressed', 'sunken')])

    def create_styled_treeview(self, parent):
        container = tk.Frame(parent, bg=self.colors['border_dark'], bd=1, relief='sunken')
        container.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)
        
        inner_frame = tk.Frame(container, bg=self.colors['table_bg'])
        inner_frame.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)
        
        vsb = ttk.Scrollbar(inner_frame, orient="vertical", style='Hacker.Vertical.TScrollbar')
        hsb = ttk.Scrollbar(inner_frame, orient="horizontal", style='Hacker.Horizontal.TScrollbar')

        columns = ('Type', 'Source', 'Destination', 'Services', 'Actions')
        tree = ttk.Treeview(
            inner_frame,
            columns=columns,
            show='headings',
            yscrollcommand=vsb.set,
            xscrollcommand=hsb.set,
            height=20,
            selectmode='extended'
        )

        vsb.config(command=tree.yview)
        hsb.config(command=tree.xview)

        column_widths = [150, 250, 250, 200, 150]
        
        headers_estilizados = [
            "   TYPE  ",
            "   SOURCE  ",
            "   DESTINATION  ",
            "   SERVICES  ",
            "   ACTIONS  "
        ]
        
        for col, width, header in zip(columns, column_widths, headers_estilizados):
            tree.heading(col, text=header, anchor='center')
            tree.column(col, width=width, minwidth=100, anchor='center')

        tree.tag_configure('ok', background='#1a3b2e')
        tree.tag_configure('odd', background=self.colors['table_row_odd'])
        tree.tag_configure('even', background=self.colors['table_row_even'])
        
        tree.tag_configure('border_top', background=self.colors['grid_line_primary'])
        tree.tag_configure('border_bottom', background=self.colors['grid_line_secondary'])

        tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')

        inner_frame.grid_rowconfigure(0, weight=1)
        inner_frame.grid_columnconfigure(0, weight=1)

        return tree

    def show_rule_details(self, event):
        selection = self.tree.selection()
        if not selection:
            return
        
        item = selection[0]
        values = self.tree.item(item, 'values')
        
        details_window = tk.Toplevel(self.root)
        details_window.title("🔍 Análisis Detallado de Regla")
        details_window.geometry("600x800")
        details_window.configure(bg=self.colors['details_bg'])
        
        details_window.transient(self.root)
        details_window.grab_set()
        
        main_frame = tk.Frame(details_window, bg=self.colors['details_bg'])
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        title_label = tk.Label(
            main_frame,
            text="╔════════════════════════════════════╗\n║     DETALLES COMPLETOS DE REGLA    ║\n╚════════════════════════════════════╝",
            font=('Consolas', 14, 'bold'),
            bg=self.colors['details_bg'],
            fg=self.colors['accent'],
            justify=tk.CENTER
        )
        title_label.pack(pady=(0, 20))
        
        details_frame = tk.Frame(main_frame, bg=self.colors['border_dark'], bd=2, relief='sunken')
        details_frame.pack(fill=tk.BOTH, expand=True)
        
        inner_details = tk.Frame(details_frame, bg=self.colors['table_bg'], bd=1, relief='raised')
        inner_details.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        
        campos = [
            ("⚡ TYPE", values[0] if values[0] else "N/A"),
            ("🌐 SOURCE", values[1] if values[1] else "N/A"),
            ("🎯 DESTINATION", values[2] if values[2] else "N/A"),
            ("🔧 SERVICES", values[3] if values[3] else "N/A"),
            ("⚙️ ACTION", values[4] if values[4] else "N/A")
        ]
        
        for i, (label, valor) in enumerate(campos):
            field_frame = tk.Frame(inner_details, bg=self.colors['table_bg'])
            field_frame.pack(fill=tk.X, padx=15, pady=10)
            
            if i > 0:
                separator = tk.Frame(inner_details, bg=self.colors['grid_line_primary'], height=1)
                separator.pack(fill=tk.X, padx=10)
            
            tk.Label(
                field_frame,
                text=label,
                font=('Segoe UI', 11, 'bold'),
                bg=self.colors['table_bg'],
                fg=self.colors['details_accent']
            ).pack(anchor='w')
            
            valor_text = tk.Text(
                field_frame,
                height=3 if len(str(valor)) > 50 else 2,
                width=50,
                bg=self.colors['table_row_odd'],
                fg=self.colors['white'],
                font=('Consolas', 10),
                wrap=tk.WORD,
                bd=1,
                relief='sunken'
            )
            valor_text.pack(fill=tk.X, pady=(5, 0))
            valor_text.insert('1.0', str(valor))
            valor_text.config(state='disabled')
        
        analysis_frame = tk.Frame(main_frame, bg=self.colors['border_dark'], bd=2, relief='sunken')
        analysis_frame.pack(fill=tk.X, pady=(20, 10))
        
        inner_analysis = tk.Frame(analysis_frame, bg=self.colors['table_bg'], bd=1, relief='raised')
        inner_analysis.pack(fill=tk.X, padx=2, pady=2)
        
        tk.Label(
            inner_analysis,
            text="ANÁLISIS DE SEGMENTACIÓN",
            font=('Segoe UI', 10, 'bold'),
            bg=self.colors['table_bg'],
            fg=self.colors['terminal_amber']
        ).pack(pady=5)
        
        source = values[1] if len(values) > 1 else ""
        destination = values[2] if len(values) > 2 else ""
        
        es_valida = self.es_valida(str(source), str(destination))
        
        if es_valida:
            resultado_text = "[+] REGLA VÁLIDA - Coincide con la segmentación"
            resultado_color = self.colors['accent']
        else:
            resultado_text = "[X] REGLA NO VÁLIDA - No coincide con la segmentación"
            resultado_color = self.colors['accent2']
        
        tk.Label(
            inner_analysis,
            text=resultado_text,
            font=('Segoe UI', 10, 'bold'),
            bg=self.colors['table_bg'],
            fg=resultado_color
        ).pack(pady=5)
        
        tk.Label(
            inner_analysis,
            text=f"Modo actual: {self.modo}",
            font=('Segoe UI', 9),
            bg=self.colors['table_bg'],
            fg=self.colors['secondary_fg']
        ).pack(pady=2)
        
        button_frame = tk.Frame(main_frame, bg=self.colors['details_bg'])
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        close_container = tk.Frame(button_frame, bg=self.colors['border_light'], bd=1, relief='raised')
        close_container.pack(side=tk.RIGHT)
        
        close_btn = tk.Button(
            close_container,
            text="🔚 CERRAR",
            command=details_window.destroy,
            bg=self.colors['secondary_bg'],
            fg=self.colors['accent'],
            font=('Segoe UI', 10, 'bold'),
            bd=0,
            padx=20,
            pady=8,
            cursor='hand2',
            activebackground=self.colors['accent'],
            activeforeground='black'
        )
        close_btn.pack()
        
        details_window.update_idletasks()
        x = (details_window.winfo_screenwidth() // 2) - (details_window.winfo_width() // 2)
        y = (details_window.winfo_screenheight() // 2) - (details_window.winfo_height() // 2)
        details_window.geometry(f'+{x}+{y}')

    def setup_ui(self):
        main_frame = tk.Frame(self.root, bg=self.colors['bg'])
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        header_frame = tk.Frame(main_frame, bg=self.colors['bg'])
        header_frame.pack(fill=tk.X, pady=(0, 20))

        title_container = tk.Frame(header_frame, bg=self.colors['border_light'], bd=1, relief='raised')
        title_container.pack(pady=5)
        
        title_label = tk.Label(
            title_container,
            text="█▓░ FIREWALL SEGMENTATION ANALYZER ░▓█",
            font=('Segoe UI', 24, 'bold'),
            bg=self.colors['bg'],
            fg=self.colors['accent'],
            padx=20,
            pady=10
        )
        title_label.pack()

        modo_container = tk.Frame(header_frame, bg=self.colors['border_light'], bd=1, relief='sunken')
        modo_container.pack(pady=5)
        
        self.modo_display = tk.Label(
            modo_container,
            text=f"► MODO: {self.modo} ◄",
            font=('Segoe UI', 16, 'bold'),
            bg=self.colors['bg'],
            fg=self.colors['terminal_amber'],
            padx=15,
            pady=5
        )
        self.modo_display.pack()

        control_container = tk.Frame(main_frame, bg=self.colors['border_dark'], bd=2, relief='raised')
        control_container.pack(fill=tk.X, pady=(0, 20))
        
        control_frame = tk.Frame(control_container, bg=self.colors['secondary_bg'], bd=1, relief='sunken')
        control_frame.pack(fill=tk.X, ipady=10, padx=2, pady=2)

        button_frame = tk.Frame(control_frame, bg=self.colors['secondary_bg'])
        button_frame.pack(expand=True)

        buttons = [
            ("↹ CAMBIAR MODO", self.cambiar_modo, self.colors['terminal_purple']),
            ("📡 CARGAR REDES CDE", self.cargar_cde, self.colors['accent']),
            ("📡 CARGAR REDES CNTO", self.cargar_cnto, self.colors['accent']),
            ("📡 CARGAR REDES NO-PCI", self.cargar_nopci, self.colors['terminal_blue']),  
            ("📊 CARGAR EXCEL", self.cargar_excel, self.colors['terminal_amber']),
            ("🔍 EJECUTAR TEST", self.ejecutar_test, self.colors['accent2']),
            ("📄 EXPORTAR HTML", self.exportar_html, self.colors['export_color'])
        ]

        for i, (text, command, color) in enumerate(buttons):
            btn_container = tk.Frame(button_frame, bg=self.colors['border_light'], bd=1, relief='raised')
            btn_container.grid(row=0, column=i, padx=5)
            
            btn = tk.Button(
                btn_container,
                text=text,
                command=command,
                bg=self.colors['secondary_bg'],
                fg=color,
                font=('Segoe UI', 11, 'bold'),
                bd=0,
                padx=15,
                pady=10,
                cursor='hand2',
                activebackground=color,
                activeforeground='black'
            )
            btn.pack()
            
            btn.bind('<Enter>', lambda e, b=btn, c=color, bc=btn_container: [
                b.config(bg=c, fg='black'),
                bc.config(bg=c)
            ])
            btn.bind('<Leave>', lambda e, b=btn, c=color, bc=btn_container: [
                b.config(bg=self.colors['secondary_bg'], fg=c),
                bc.config(bg=self.colors['border_light'])
            ])

        stats_container = tk.Frame(main_frame, bg=self.colors['border_dark'], bd=2, relief='sunken')
        stats_container.pack(fill=tk.X, pady=(0, 10))
        
        stats_frame = tk.Frame(stats_container, bg=self.colors['bg'], bd=1, relief='raised')
        stats_frame.pack(fill=tk.X, padx=2, pady=2)


        self.stats_labels = {}
        stats_info = [
            ('📁 CDE:', '0 redes', self.colors['accent']),
            ('📁 CNTO:', '0 redes', self.colors['terminal_amber']),
            ('📁 NO-PCI:', '0 redes', self.colors['terminal_blue']), 
            ('📊 Excel:', 'No cargado', self.colors['terminal_purple']),
            ('📄 Reglas:', '0', self.colors['accent2'])
        ]

        for i, (label, value, color) in enumerate(stats_info):
            frame = tk.Frame(stats_frame, bg=self.colors['bg'])
            frame.pack(side=tk.LEFT, padx=20)
            
            if i > 0:
                separator = tk.Frame(stats_frame, bg=self.colors['grid_line_primary'], width=2)
                separator.pack(side=tk.LEFT, fill=tk.Y, padx=5)
            
            tk.Label(
                frame,
                text=label,
                font=('Segoe UI', 10, 'bold'),
                bg=self.colors['bg'],
                fg=color
            ).pack(side=tk.LEFT)
            
            self.stats_labels[label] = tk.Label(
                frame,
                text=value,
                font=('Segoe UI', 10),
                bg=self.colors['bg'],
                fg=self.colors['secondary_fg']
            )
            self.stats_labels[label].pack(side=tk.LEFT, padx=(5, 0))

        table_container = tk.Frame(main_frame, bg=self.colors['border_dark'], bd=3, relief='sunken')
        table_container.pack(fill=tk.BOTH, expand=True)
        
        self.tree = self.create_styled_treeview(table_container)
        
        self.tree.bind('<Double-1>', self.show_rule_details)

        footer_container = tk.Frame(main_frame, bg=self.colors['border_dark'], bd=2, relief='raised')
        footer_container.pack(fill=tk.X, pady=(10, 0))
        
        footer_frame = tk.Frame(footer_container, bg=self.colors['bg'], bd=1, relief='sunken')
        footer_frame.pack(fill=tk.X, padx=2, pady=2)

        tk.Label(
            footer_frame,
            text="[SISTEMA LISTO]",
            font=('Segoe UI', 9, 'bold'),
            bg=self.colors['bg'],
            fg=self.colors['accent']
        ).pack(side=tk.LEFT, padx=10)

        self.status_label = tk.Label(
            footer_frame,
            text="Esperando datos...",
            font=('Segoe UI', 9),
            bg=self.colors['bg'],
            fg=self.colors['secondary_fg']
        )
        self.status_label.pack(side=tk.LEFT, padx=(20, 0))

        credits_frame = tk.Frame(self.root, bg=self.colors['bg'])
        credits_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=(0, 10))
        
        tk.Label(credits_frame, text="", bg=self.colors['bg']).pack(side=tk.LEFT, expand=True, fill=tk.X)
        
        credits_label = tk.Label(
            credits_frame,
            text="Developed by: R3LI4NT",
            font=('Segoe UI', 10, 'italic'),
            bg=self.colors['bg'],
            fg=self.colors['white']
        )
        credits_label.pack(side=tk.RIGHT)

    def animate_title(self):
        colors = [self.colors['accent'], 
                 self.colors['terminal_amber'], 
                 self.colors['terminal_purple']]
        
        def change_color(idx=0):
            self.modo_display.config(fg=colors[idx % len(colors)])
            self.root.after(500, change_color, idx + 1)
        
        change_color()

    def cambiar_modo(self):
        modos = ["CDE → CNTO", "CNTO → CDE", "NO-PCI → CDE/CNTO"]
        current_index = modos.index(self.modo)
        self.modo = modos[(current_index + 1) % len(modos)]
        
        self.modo_display.config(text=f"► MODO: {self.modo} ◄")
        self.status_label.config(text=f"Modo cambiado a {self.modo}")

    def cargar_cde(self):
        filename = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if filename:
            with open(filename) as f:
                self.CDE_PREFIXES = [line.strip() for line in f if line.strip()]
            self.stats_labels['📁 CDE:'].config(text=f"{len(self.CDE_PREFIXES)} redes")
            self.status_label.config(text=f"✓ CDE: {len(self.CDE_PREFIXES)} redes cargadas")

    def cargar_cnto(self):
        filename = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if filename:
            with open(filename) as f:
                self.CNTO_PREFIXES = [line.strip() for line in f if line.strip()]
            self.stats_labels['📁 CNTO:'].config(text=f"{len(self.CNTO_PREFIXES)} redes")
            self.status_label.config(text=f"✓ CNTO: {len(self.CNTO_PREFIXES)} redes cargadas")

    def cargar_nopci(self):
        filename = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if filename:
            with open(filename) as f:
                self.NOPCI_PREFIXES = [line.strip() for line in f if line.strip()]
            self.stats_labels['📁 NO-PCI:'].config(text=f"{len(self.NOPCI_PREFIXES)} redes")
            self.status_label.config(text=f"✓ NO-PCI: {len(self.NOPCI_PREFIXES)} redes cargadas")

    def cargar_excel(self):
        filename = filedialog.askopenfilename(filetypes=[("Excel files", "*.xlsx *.xls")])
        if filename:
            self.df = pd.read_excel(filename)
            self.stats_labels['📊 Excel:'].config(text=f"{len(self.df)} filas")
            self.status_label.config(text=f"✓ Excel cargado: {len(self.df)} reglas")

    def detectar_columnas(self):
        columnas = list(self.df.columns)
        
        source_col = None
        dest_col = None
        type_col = None
        services_col = None
        actions_col = None
        
        for col in columnas:
            col_l = col.lower()
            
            if any(x in col_l for x in ["source", "src", "origen"]):
                source_col = col
            elif any(x in col_l for x in ["destination", "dest", "dst", "destino"]):
                dest_col = col
            elif "type" in col_l:
                type_col = col
            elif any(x in col_l for x in ["service", "application", "services"]):
                services_col = col
            elif "action" in col_l:
                actions_col = col
        
        return type_col, source_col, dest_col, services_col, actions_col

    def es_valida(self, source, destination):
        source = str(source)
        destination = str(destination)
        
        if self.modo == "CDE → CNTO":
            return (
                any(pref in source for pref in self.CDE_PREFIXES)
                and
                any(pref in destination for pref in self.CNTO_PREFIXES)
            )
        
        if self.modo == "CNTO → CDE":
            return (
                any(pref in source for pref in self.CNTO_PREFIXES)
                and
                any(pref in destination for pref in self.CDE_PREFIXES)
            )
        
        if self.modo == "NO-PCI → CDE/CNTO":
            return (
                any(pref in source for pref in self.NOPCI_PREFIXES)
                and
                (any(pref in destination for pref in self.CDE_PREFIXES) or
                 any(pref in destination for pref in self.CNTO_PREFIXES))
            )
        
        return False

    def ejecutar_test(self):
        if self.df is None:
            messagebox.showwarning("[!] Error", "Cargar Excel primero")
            return
        
        if not self.CDE_PREFIXES or not self.CNTO_PREFIXES:
            messagebox.showwarning("[!] Error", "Cargar redes CDE y CNTO primero")
            return
        
        if self.modo == "NO-PCI → CDE/CNTO" and not self.NOPCI_PREFIXES:
            messagebox.showwarning("[!] Error", "Modo NO-PCI requiere cargar redes NO-PCI primero")
            return
        
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        type_col, source_col, dest_col, services_col, actions_col = self.detectar_columnas()
        
        if not source_col or not dest_col:
            messagebox.showerror("[X] Error", "No se detectaron columnas Source/Destination")
            return
        
        total = 0
        self.ultimos_resultados = []
        
        for idx, (_, row) in enumerate(self.df.iterrows()):
            source = str(row[source_col])
            destination = str(row[dest_col])
            
            if not self.es_valida(source, destination):
                continue
            
            total += 1
            
            tag = 'even' if idx % 2 == 0 else 'odd'
            
            resultado = {
                'Type': str(row[type_col]) if type_col else "N/A",
                'Source': source,
                'Destination': destination,
                'Services': str(row[services_col]) if services_col else "ANY",
                'Actions': str(row[actions_col]) if actions_col else "permit",
                'Description': f"Regla {total} en modo {self.modo}"
            }
            self.ultimos_resultados.append(resultado)
            
            self.tree.insert("", tk.END, values=(
                resultado['Type'],
                resultado['Source'],
                resultado['Destination'],
                resultado['Services'],
                resultado['Actions']
            ), tags=('ok', tag))
        
        self.stats_labels['📄 Reglas:'].config(text=str(total))
        self.status_label.config(text=f"[+] Análisis completado: {total} reglas encontradas")

    def exportar_html(self):
        if not self.ultimos_resultados:
            messagebox.showwarning("[!] Error", "No hay resultados para exportar. Ejecuta un test primero.")
            return
        
        nombre_cliente = simpledialog.askstring("Nombre del Cliente", "Ingrese el nombre del cliente:", parent=self.root)
        
        if not nombre_cliente:
            nombre_cliente = "CLIENTE"
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML files", "*.html"), ("All files", "*.*")],
            title="Guardar reporte HTML como...",
            initialfile=f"RulesAudit_{nombre_cliente}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        )
        
        if not filename:
            return
        
        try:
            stats = {
                'cde': len(self.CDE_PREFIXES),
                'cnto': len(self.CNTO_PREFIXES),
                'nopci': len(self.NOPCI_PREFIXES)
            }
            
            generar_reporte_html(
                resultados=self.ultimos_resultados,
                modo_actual=self.modo,
                stats=stats,
                cde_prefixes=self.CDE_PREFIXES,
                cnto_prefixes=self.CNTO_PREFIXES,
                nopci_prefixes=self.NOPCI_PREFIXES,
                nombre_archivo_original=os.path.basename(filename),
                ruta_salida=filename,
                nombre_cliente=nombre_cliente
            )
            
            messagebox.showinfo("[+] Éxito", f"Reporte HTML generado:\n{filename}")
            self.status_label.config(text=f"[+] Reporte exportado: {os.path.basename(filename)}")
            
        except Exception as e:
            messagebox.showerror("[X] Error", f"Error al generar reporte:\n{str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = FirewallSegmentacionApp(root)
    root.mainloop()