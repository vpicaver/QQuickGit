# This Python file uses the following encoding: utf-8

# if __name__ == "__main__":
#     pass


# from conans import ConanFile, CMake, tools
# import os, sys

from conan import ConanFile
from conan.tools.cmake import CMake
from conan.tools.cmake import CMakeDeps
# from conan.tools.env import VirtualRunEnv
from conan.tools import files
import os


class QQuickGitConan(ConanFile):
    name = "QQuickGit"
    author = "Philip Schuchardt vpicaver@gmail.com"
    description = "Decenteralize mobile GIS"
    topics = ("gis")
    version = "1.0"
    settings = "os", "compiler", "build_type", "arch"
    generators = "VirtualBuildEnv", "VirtualRunEnv","CMakeToolchain","CMakeDeps"

    def requirements(self):
        self.requires("catch2/3.7.1")

        self.requires("libgit2/1.8.4") #[>=1.3]")
        #self.requires("libgit2/1.5.0") #[>=1.3]") #1.5.0, 1.4.3 doesn't seem work with iOS or Android
        
        #For android we should build WSL (on windows) and host it off a local server, because
        #it's not possible to build openssl on windows because it doesn't have a proper shell
        if self.settings.os == "Android":
            #self.requires("openssl/1.1.1@demo/testing")
            #self.requires("openssl/3.1.1@demo/testing")
            self.requires("openssl/3.5.0")
        else:
            self.requires("openssl/3.5.0")
                
            #This uses master branch, tested macos and ios on libssh2/dd0b5b2d2b8f5ef7af826e1e1aa1d48a0442c351
            #1.10 doesn't support RSA with sha256, the master branch does
            #Without RSA sha256, github rejects the ssh connection for cloning or pushing
            #once 1.11 is released, we can switch back to using the offical vesion
            #The master is also currently broken. On Android 12 and 13, I get Invalid Mac Address
            #when cloning repositories with libgit2
            # self.requires("libssh2/master@demo/testing")
            self.requires("libssh2/[>=1.11]")

            if self.settings.os == "Windows":
                self.requires("libiconv/[>=1.0]")

    def configure(self):
            self.options["openssl"].shared = True

            #if self.settings.os == "Android":
                #self.options["openssl"].shared = False
                #self.options["openssl"].no_asm = True #Windows building android, probably can comment out for other platforms

            if self.settings.os == "iOS":
                self.options["openssl"].shared = False
                self.options["sqlite3"].build_executable = False
                self.options["libgit2"].with_regex = "builtin"
