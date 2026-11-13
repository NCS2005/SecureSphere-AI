# MVSR Engineering College -- general project-report LaTeX template

This is a reusable template based on the uploaded 2025--26 title page, front-paper sample, report-format guidance, and the example LaTeX report. The example project's topic, student identifiers and reported results have been removed.

## Use
1. Edit `config.tex` for title, branch, year, students, guide, head of department and other names.
2. Replace the placeholder content in `frontmatter/abstract.tex` and `chapters/*.tex` with actual project material.
3. Replace or verify `images/MVSR_logo.jpg` if the college provides a higher-resolution approved logo.
4. From the project folder, run `xelatex main.tex` twice to generate `main.pdf` with correct contents and page references. In Overleaf set compiler to **XeLaTeX**.
5. For industry projects, uncomment the optional industry certificate in `main.tex` and replace it with the approved certificate.

## Format implemented
- A4; 1.5-inch left margin and 1-inch other margins
- 12-point Times New Roman when installed, otherwise Times-compatible TeX Gyre Termes
- 1.5 line spacing and 6-point paragraph spacing
- 14-point centered uppercase chapter titles; 12-point sections
- project name header; department footer; right-aligned arabic page numbers starting at chapter 1
- lower-case roman front matter numbering starting with certificate (title unnumbered)
- automatic contents, list of tables and figures; chapter-based figure/table/equation numbering
- front pages, six chapter shells, references and appendix

## Important notes
- The guidance says the final project report should normally be **50--60 pages, excluding appendix**. The distributed template has placeholder content and is deliberately shorter.
- Replace all placeholders, verify official names/designations, and obtain the guide's approval before printing.
- Title page should be printed in colour. Final binding instructions are in the supplied institutional guidelines.
- Department vision/mission and project objectives/outcomes are transcribed from the supplied sample and should be confirmed against current departmental wording.
- The uploaded source contains conflicting older examples. This generic template gives precedence to the uploaded **2025--26 CSE-Allied report-format and front-papers** documents rather than the older GitHub-specific sample.
