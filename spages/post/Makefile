.PHONY: view

FILE_NAME:=ajda

build:
	pandoc \
    --from=markdown \
    --to=html \
    --template=./templates/newcss.html \
    --toc \
    --standalon \
    --resource-path=.:diagrams \
    --fail-if-warning \
    -f commonmark_x \
    -o $(FILE_NAME).html \
    $(FILE_NAME).md

view:
	(firefox ./$(FILE_NAME).html)&

clean:
	rm -f $(FILE_NAME).html
