plotprocmoncsv -sp -t "Ransomware Example 1" -f ../gallery/procmoncsv/ransomware_example1.html /Source/Procmon\ CSV/Ransomware_focused.csv
plotprocmoncsv -sp -t "Ransomware Example 2" -f ../gallery/procmoncsv/ransomware_example2.html /Source/Procmon\ CSV/Ransomware.csv
plotprocmoncsv -sp -t "Ransomware Example 3" -pt -pu -sh -f ../gallery/procmoncsv/ransomware_example3.html /Source/Procmon\ CSV/Ransomware.csv
plotprocmoncsv -t "Ransomware Example 4" -pfw -pfd -pfn -sp -f ../gallery/procmoncsv/ransomware_example4.html /Source/Procmon\ CSV/Ransomware_focused.csv
plotprocmoncsv -t "Ransomware Example 5" -pfw -pfd -pfn -sp -f ../gallery/procmoncsv/ransomware_example5.html /Source/Procmon\ CSV/Ransomware.csv
plotprocmoncsv -t "Ransomware Example 6" -prw -prd -sp -f ../gallery/procmoncsv/ransomware_example6.html /Source/Procmon\ CSV/Ransomware_focused.csv
plotcuckoojson -t "Ransomware Example 1" -f ../gallery/cuckoojson/ransomware_example1.html -fa -na -ra -gp dot /Source/cuckoo-modified-json/3_report.json
plotcuckoojson -t "Ransomware Example 2" -f ../gallery/cuckoojson/ransomware_example2.html -fa -ra /Source/cuckoo-modified-json/3_report.json
plotcuckoojson -t "Ransomware Example 3" -f ../gallery/cuckoojson/ransomware_example3.html -na -ra /Source/cuckoo-modified-json/3_report.json
plotcuckoojson -t "Ransomware Example 4" -f ../gallery/cuckoojson/ransomware_example4.html -na -fa /Source/cuckoo-modified-json/3_report.json
