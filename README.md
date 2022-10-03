# Golden Image Finalizer

Shamelessly forked and modified on the original wonderful work by @jzavcer at his [repository](https://github.com/jzavcer/VDI-Windows-Finalize)

## Usage

### Normal

```powershell
./Golden-Image-Finalizer.ps1
```

Note that some parts of the process may require user input (_e.g. the prompt for disk cleanup seems to require some form of user input_).

### Via `iex`

```powershell
Set-ExecutionPolicy -Scope CurrentUser Unrestricted
iex (iwr 'https://github.com/lflare/golden-image-finalizer/raw/master/Golden-Image-Finalizer.ps1')
```

Note that execution policy has to allow for the execution of scripts or the above will fail.

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License

[AGPLv3](./LICENSE)
