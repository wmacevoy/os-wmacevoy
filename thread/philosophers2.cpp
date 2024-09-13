#include <mutex>
#include <iostream>
#include <thread>
#include <mutex>
#include <chrono>
#include <functional>
#include <vector>

// random value in [a,b)
uint32_t rand(uint32_t a, uint32_t b) {
  return a + ((b > a)?rand() % (b-a) : 0);
}


void msSleep(uint32_t ms) {
  std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}

//
// Console log as a shared resource; all threads access this log.
//
class Log {
private:
  std::mutex mutex;
  std::ostream &out;
public:
  Log(std::ostream &_out) : out(_out) {}
  void note(std::function < void (std::ostream &out) > print) {
    std::lock_guard < std::mutex > gaurd(mutex);
    print(out); out << std::endl;
  }
};

Log logger(std::cout);

// NOTE sends a single message to the logger
#define NOTE(MSG) logger.note([&](auto &out) { out << MSG; })

//
// Fork is a shared resource - two philosophers will want to access each fork
//
class Fork {
public:
  using Guard = std::shared_ptr < Fork >;
  using Ptr = std::shared_ptr < Fork >;

  const int id;
private:
  std::timed_mutex baton;
  
public:
  Fork(int _id)
    : id(_id) {}

  // returns a shared_ptr of this fork if
  // sucessful in locking the mutex within
  // the msTimeout.  The shared ptr releases
  // the lock when exiting scope.
  //
  Guard pickup(uint32_t msTimeout) {
    if (baton.try_lock_for(std::chrono::milliseconds(msTimeout))) {
      // ususual use of shared_ptr, it refers to this fork,
      // but the destructor releases the lock.
      return std::shared_ptr < Fork > (this , [&](Fork *me) { me->baton.unlock(); });
    } else {
      // lock aquisition failed, return a null shared pointer
      return std::shared_ptr < Fork > (nullptr);
    }
  }

  Guard pickup() {
    baton.lock();
    return std::shared_ptr < Fork > (this , [&](Fork *me) { me->baton.unlock(); });
  }
};

//
// #size philosophers are in a room and they think (independently) or eat,
// to eat they sit at their spot at a round table and pick up the forks
// on the left and right, then eat, put them down, and go back to thinking.
//
class Philosopher {
public:
  const int id;
private:
  std::atomic<bool> alive;
  Fork::Ptr leftFork;
  Fork::Ptr rightFork;
  std::shared_ptr < std::thread > thread;
public:
  Philosopher(int _id, Fork::Ptr _leftFork, Fork::Ptr _rightFork)
    : id(_id), alive(false), leftFork(_leftFork), rightFork(_rightFork) {}

  void start() {
    alive = true;
    thread = std::make_shared < std::thread > (&Philosopher::live, this);
  }

  void stop() {
    alive = false;
  }
  
  void join() {
    alive = false;
    if (thread) {
      thread->join();
    }
    thread = nullptr;
  }

private:
  void live() {
    NOTE("Philosopher " << id << " is alive.");
    while (alive) {
      think();
      eat();
    }
    NOTE("Philosopher " << id << " is dead.");
  }
  
  void think() {
    NOTE("Philosopher " << id << " is thinking.");
    std::this_thread::sleep_for(std::chrono::milliseconds(rand(500,1500)));
  }
  
  void eat() {
    NOTE("Philosopher " << id << " is hungry.");
    auto leftBaton = leftFork->pickup();
    // add pause to create more lock conflicts
    std::this_thread::sleep_for(std::chrono::milliseconds(rand(250,500)));
    NOTE("Philosopher " << id << " got left fork " << leftFork->id << ".");
    auto rightBaton = rightFork->pickup(rand(500,1500));
    if (!rightBaton) {
      NOTE("Philosopher " << id << " leaves the table hungry.");
      return;
    }
    NOTE("Philosopher " << id << " got right fork " << rightFork->id << ".");

    NOTE("Philosopher " << id << " is eating.");
    std::this_thread::sleep_for(std::chrono::milliseconds(rand(500,1500)));
  }
};

class Room {
public:
  const size_t size;
  std::vector < std::shared_ptr < Fork > > forks;
  std::vector < std::shared_ptr < Philosopher > > philosophers;
  Room(size_t _size) : size(_size), forks(size), philosophers(size) {
    for (size_t id = 0; id<size; ++id) {
      forks[id] = std::make_shared < Fork > (id);
    }
    
    for (size_t id = 0; id<size; ++id) {
      Fork::Ptr left = forks[id];
      Fork::Ptr right = forks[(id+1) % size];
      philosophers[id] = std::make_shared < Philosopher > (id, left, right);
    }
  }

  void start() {
    for (size_t id = 0; id != size; ++id) {
      philosophers[id]->start();
    }
  }

  void stop() {
    for (size_t id = 0; id != size; ++id) {
      philosophers[id]->stop();
    }
  }

  void join() {
    for (size_t id = 0; id<size; ++id) {
      philosophers[id]->join();
    }
  }
};

//
// helper to process command line options,
// if arg starts with prefix,
// then run lambda on the rest of arg (returning true)
// otherwise return false
//
bool option(const std::string &arg,
	const std::string &pfx,
	std::function<void (const char *rest)> match) {
  if (arg.compare(0,pfx.size(),pfx) == 0) {
    const char *rest=arg.c_str()+pfx.size();
    match(rest);
    return true;
  }
  return false;
}

int main(int argc, const char *argv[]) {
  size_t size = 4;
  int time = 10;
  
  for (int i=1; i<argc; ++i) {
    std::string arg=argv[i];
    if (option(arg,"--size=",[&](auto _size) { size = atoi(_size); })) continue;
    if (option(arg,"--time=",[&](auto _time) { time = atoi(_time); })) continue;
    std::cout << "unknown argument " << arg << std::endl;
  }

  auto room = std::make_shared <Room>(size);

  room->start();
  std::this_thread::sleep_for(std::chrono::seconds(time));
  room->stop();
  room->join();

  return 0;

}

