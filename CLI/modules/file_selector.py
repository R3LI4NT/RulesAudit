# Módulo para selección de archivos (CLI con diálogos Tkinter)

import tkinter as tk
from tkinter import filedialog


def seleccionar_archivo_excel():
    raiz = tk.Tk()
    raiz.withdraw()
    raiz.lift()
    raiz.focus_force()

    print("\nPresiona ENTER para seleccionar el archivo Excel con las reglas...")
    input()

    ruta_excel = filedialog.askopenfilename(
        title="Selecciona el archivo Excel de reglas",
        filetypes=[
            ("Archivos Excel", "*.xlsx *.xls"),
            ("Todos los archivos", "*.*")
        ]
    )

    raiz.destroy()
    return ruta_excel if ruta_excel else None


def seleccionar_archivo_json():
    raiz = tk.Tk()
    raiz.withdraw()
    raiz.lift()
    raiz.focus_force()

    print("\nPresiona ENTER para seleccionar el archivo JSON de vulnerabilidades...")
    input()

    ruta_json = filedialog.askopenfilename(
        title="Selecciona el archivo JSON de vulnerabilidades",
        filetypes=[
            ("Archivos JSON", "*.json"),
            ("Todos los archivos", "*.*")
        ]
    )

    raiz.destroy()
    return ruta_json if ruta_json else None


def seleccionar_carpeta_destino():
    raiz = tk.Tk()
    raiz.withdraw()
    raiz.lift()
    raiz.focus_force()

    print("\nPresiona ENTER para seleccionar la carpeta de destino...")
    input()

    carpeta = filedialog.askdirectory(
        title="Selecciona la carpeta donde guardar los resultados"
    )

    raiz.destroy()
    return carpeta if carpeta else None
