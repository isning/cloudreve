# Source-pinned test tooling; runtime storage credentials remain fixture-generated.
let
  pkgs = import (builtins.getFlake "github:NixOS/nixpkgs/7fd4004d0511991fff3a0524856a9be09e28c5f0").outPath {};
in pkgs.symlinkJoin {
  name = "cloudreve-storage-test-tools";
  paths = [ pkgs.seaweedfs pkgs.ffmpeg ];
}
