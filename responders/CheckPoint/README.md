### CkeckPoint

This responder permits you to add/remove selected observable from a specific group. 

Some notes:

    - API must permit access from cortex machine.

    - First login from API must be manual because it needs fingerprint acceptance. This will generate a fingerprints.txt file that must be placed near to the analyzer python file.

    - It doesn't work in dockerized analyzer!

    - If group doesn't exists it'll be created [when blocking]. At the moment without any default rule.


#### Requirements
The following options are required in CheckPoint Responder configuration:

- `server` : URL of CheckPoint instance 
- `username`: user accessing CheckPoint instance
- `password`:  password for the user accessing CheckPoint instance
- `group_name`: name of the group ip will be added to or removed
