# FireEye_AX Analyzer by Unit777

## Sample configuration

```
analyzer {
    ....
    config {
        ....
        FireEye_AX {
            username="username"
            password="password"
            url="https://xxx.xxx.xxx.xxx/wsapis/v1.1.0/"
        }
    }
}
```

## Specify sandbox configuration
You can modify/specify configuration for your FireEye AX appliance in fireeye_ax_file.json. A sample sandbox options is given below.

```
"sandbox_options": {
            "analysistype": "0",
            "timeout": "180",
            "priority": "0",
            "profiles": ["winxp-sp3"],
            "application": "0",
            "force": "true",
            "prefetch": "1"
        }
```