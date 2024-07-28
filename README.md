# Securiter

Securiter es una extensión para Visual Studio Code que analiza otras extensiones en búsqueda de código malicioso.

## Características

- Detecta uso de `exec` con comandos potencialmente peligrosos.
- Encuentra y registra todas las URLs sin marcarlas como maliciosas.
- Muestra advertencias si se encuentra código sospechoso.

![Analyzing Extensions](images/icon.png)

## Uso

Para usar la herramienta simplemente use: ```ctrl+shift+p``` y seleccionar * Analyze Extensions.

## Requisitos

No hay requisitos adicionales para esta extensión.

## Configuración de la Extensión

Esta extensión no agrega configuraciones adicionales a Visual Studio Code.

## Problemas Conocidos

No se han reportado problemas conocidos hasta el momento.

## Notas de la Versión

### 1.0.0

Lanzamiento inicial de Securiter.

- Detección de URLs.
- Mejora en la detección de comandos peligrosos.

### 1.0.1

Corrección de errores menores.

- Archivo guardado en documentos.
- Mas comandos que se pueden detectar como maliciosos.

---

## Siguiendo las Directrices de Extensiones

Asegúrate de haber leído las directrices para extensiones y seguir las mejores prácticas para crear tu extensión.

* [Directrices de Extensiones](https://code.visualstudio.com/api/references/extension-guidelines)

## Para más información

* [Soporte de Markdown en Visual Studio Code](http://code.visualstudio.com/docs/languages/markdown)
* [Referencia de Sintaxis de Markdown](https://help.github.com/articles/markdown-basics/)

**¡Disfruta!**
