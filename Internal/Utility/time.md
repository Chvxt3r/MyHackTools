# FakeTime
## Install
```
sudo apt install libfaketime
```
## Usage
- Sync your time with a destination time server for once command only
  ```bash
  faketime "$(ntpdate -q <ip of timesource> | cut -d'' -f 1,2)" <command>
  ```
- Add a set amount of time to your command
  ```bash
  faketime -f '+7h' <command>
  ```
