build: Dockerfile hello.cpp
	docker build -t cpp-hello-world . && touch build
run: build
	docker run --rm cpp-hello-world
clean:
	docker rmi cpp-hello-world
CHAT=https://chatgpt.com/share/6793d34e-b334-8009-893b-0e8845939d10
chat:
	@if [ "$(OS)" = "Windows_NT" ]; then \
		start $(CHAT); \
	elif command -v xdg-open > /dev/null; then \
		xdg-open $(CHAT); \
	else \
		open $(CHAT); \
	fi