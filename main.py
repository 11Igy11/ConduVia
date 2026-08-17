import multiprocessing
import sys


def _run_pcap_isolated_child() -> bool:
    """Headless PCAP worker mode for PyInstaller builds (avoids spawning a second GUI)."""
    if len(sys.argv) < 2 or sys.argv[1] != "--pcap-isolated":
        return False
    from core.pcap_isolated import main as pcap_isolated_main

    raise SystemExit(pcap_isolated_main(sys.argv[2:]))


def main() -> None:
    if _run_pcap_isolated_child():
        return
    multiprocessing.freeze_support()
    from ui.app import main as run_gui

    run_gui()


if __name__ == "__main__":
    main()
