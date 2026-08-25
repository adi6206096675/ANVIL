# engine/chaos/xeus.py
import multiprocessing
import time
import os
import psutil

class AnvilXeus:
    """
    The 'Hydraulic Press' module.
    Artificially starves the environment of CPU and Memory to test application resilience.
    """
    def __init__(self, target_cpu_percent: int = 90, memory_mb_to_consume: int = 1024):
        self.target_cpu = target_cpu_percent
        self.memory_mb = memory_mb_to_consume
        self.processes = []
        self._memory_hog = []

    def _cpu_burner(self):
        """Infinite loop of heavy arithmetic to pin CPU cores to 100%."""
        while True:
            _ = [x**2 for x in range(10000)]

    def engage_pressure(self):
        print("\n" + "⚠️ "*25)
        print("   ANVIL XEUS ENGAGED: APPLYING HYDRAULIC PRESSURE")
        print("⚠️ "*25)
        
        # 1. RAM Starvation
        print(f"[XEUS] Allocating {self.memory_mb} MB of dead memory...")
        try:
            # Allocate 1MB chunks of random bytes
            for _ in range(self.memory_mb):
                self._memory_hog.append(bytearray(os.urandom(1024 * 1024)))
        except MemoryError:
            print("[XEUS] Maximum memory threshold reached.")

        # 2. CPU Starvation
        cores_to_use = max(1, multiprocessing.cpu_count() - 1)
        print(f"[XEUS] Igniting {cores_to_use} CPU cores to simulate extreme load...")
        
        for _ in range(cores_to_use):
            p = multiprocessing.Process(target=self._cpu_burner)
            p.daemon = True
            p.start()
            self.processes.append(p)

        print(f"[XEUS] Environmental pressure stabilized. Current System CPU: {psutil.cpu_percent()}%")

    def release_pressure(self):
        """Kills the starvation threads and releases memory."""
        for p in self.processes:
            p.terminate()
            p.join()
        
        self._memory_hog.clear()
        print("[XEUS] Pressure released. System returning to nominal state.\n")

if __name__ == "__main__":
    xeus = AnvilXeus(memory_mb_to_consume=500)
    xeus.engage_pressure()
    time.sleep(5) # Hold pressure for 5 seconds
    xeus.release_pressure()