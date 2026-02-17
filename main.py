from core.loader import load_folder
from core.analyzer import (
    top_src_ips,
    top_dst_ips,
    top_protocols,
    top_applications,
    top_src_ips_by_bytes,
    top_dst_ips_by_bytes,
    top_apps_by_bytes,
    top_sni_by_bytes,
    top_flows_by_bytes,
)


DATA_FOLDER = r"C:\Users\igi_t\Desktop\Projekti\Conduvia\data"
WHITELIST_SNI = [
    # dodaj što god smatraš normalnim; može biti i prazno
    "apple.com",
    "google.com",
    "microsoft.com",
    "akadns.net",
    "cloudfront.net",
    "akamai",
]



def main() -> None:
    folder = DATA_FOLDER

    files, flows = load_folder(folder, debug=False)

    print(f"Data folder: {folder}")
    print(f"JSON files: {len(files)}")
    print(f"Total flow records: {len(flows)}")

    # ---- COUNTS ----
    print("\nTop 10 source IPs (by flow count):")
    for ip, count in top_src_ips(flows, limit=10):
        print(f"{ip:20} {count}")

    print("\nTop 10 destination IPs (by flow count):")
    for ip, count in top_dst_ips(flows, limit=10):
        print(f"{ip:20} {count}")

    print("\nTop 10 protocols (by flow count):")
    for proto, count in top_protocols(flows, limit=10):
        print(f"{proto:20} {count}")

    print("\nTop 10 applications (by flow count):")
    for app, count in top_applications(flows, limit=10):
        print(f"{app:30} {count}")

    # ---- BYTES ----
    print("\nTop 10 source IPs by BYTES:")
    for ip, total in top_src_ips_by_bytes(flows, limit=10):
        print(f"{ip:20} {total}")

    print("\nTop 10 destination IPs by BYTES:")
    for ip, total in top_dst_ips_by_bytes(flows, limit=10):
        print(f"{ip:20} {total}")

    print("\nTop 10 applications by BYTES:")
    for app, total in top_apps_by_bytes(flows, limit=10):
        print(f"{app:30} {total}")

    print("\nTop 10 requested_server_name by BYTES:")
    for sni, total in top_sni_by_bytes(flowslows := flows, limit=10):
        print(f"{sni:60} {total}")
        
        print("\nTop SNI by BYTES (excluding whitelist):")
    excluded = 0
    shown = 0
    for sni, total in top_sni_by_bytes(flows, limit=200):
        sni_l = sni.lower()
        if any(x in sni_l for x in WHITELIST_SNI):
            excluded += 1
            continue
        print(f"{sni:60} {total}")
        shown += 1
        if shown >= 20:
            break
    print(f"(excluded {excluded} whitelisted entries)")


    print("\nTop 10 biggest flows (by bytes):")
    for row in top_flows_by_bytes(flows, limit=10):
        print(row)


if __name__ == "__main__":
    main()
