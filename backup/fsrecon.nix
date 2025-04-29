{ lib
, stdenv
, nmap
, subfinder
, gobuster
, httpx
, gowitness
, nuclei
, makeWrapper
, bash
, ...
}:

stdenv.mkDerivation {
  pname = "fsrecon";
  version = "1.0"; # Match your script version
  
  # Use the current directory as the source
  src = ./.;
  
  # List the tools your script depends on
  nativeBuildInputs = [ makeWrapper ];
  
  buildInputs = [
    bash
  ];
  
  # Fix the installPhase to correctly handle the script and its dependencies
  installPhase = ''
    mkdir -p $out/bin
    cp FSRecon.sh $out/bin/fsrecon
    chmod +x $out/bin/fsrecon
    
    # Wrap the script with the necessary runtime dependencies in PATH
    wrapProgram $out/bin/fsrecon \
      --prefix PATH : ${lib.makeBinPath [
        nmap
        subfinder
        gobuster
        httpx
        gowitness
        nuclei
        # Add other tools here if you use them
      ]}
  '';
  
  meta = with lib; {
    description = "A modular domain reconnaissance framework";
    # Replace with your repository URL if you plan to share this
    homepage = "https://github.com/AsyuTheAnonymous/FSRecon";
    license = licenses.free; # Or choose an appropriate license for your script
    platforms = platforms.linux;
    maintainers = [];
  };
}