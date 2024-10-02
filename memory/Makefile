CXXFLAGS=-std=c++17 -O3 -g

memory : memory.cpp
	$(CXX) -o $@ $(CXXFLAGS) $< $(LDFLAGS)
memory2 : memory2.cpp
	$(CXX) -o $@ $(CXXFLAGS) $< $(LDFLAGS)
benchmarks2: memory2
	./memory2 vector row-major
	./memory2 array row-major
	./memory2 vector column-major
	./memory2 array column-major
memory2.s : memory2.cpp
	g++ $(CXXFLAGS) -fverbose-asm -S memory2.cpp -o memory2.s

memory3 : memory3.cpp
	$(CXX) -o $@ $(CXXFLAGS) $< $(LDFLAGS)

benchmarks3: memory3
	./memory3 vector row-major
	./memory3 array row-major
	./memory3 vector column-major
	./memory3 array column-major

memory3.s : memory3.cpp
	g++ $(CXXFLAGS) -fverbose-asm -S memory3.cpp -o memory3.s