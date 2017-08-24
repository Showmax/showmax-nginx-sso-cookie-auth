# Showmax Specific Stuff

We decided to release the package as an open source (T26405). That brings certain challenges in the way how we release the package. We need to be able to store Showmax specific changes/configuration away from the actual code. One option is to have a configuration file, but that sort of sucks within the nginx lua ecosystem. Therefore I've chosen using patches (via debian patch-queue or pq) for updating the configuration.

We are also using `git-buildpackage` for managing the build process. Good source of information is http://honk.sigxcpu.org/projects/git-buildpackage/manual-html/gbp.html

The basic workflow is as follows
  - changes which should got to public release are made in `upstream` branch
  - changes specific to Showmax go to `master` branch. If you are touching the files which are also in public release, you **have** to use patch-queue workflow. Check http://honk.sigxcpu.org/projects/git-buildpackage/manual-html/gbp.patches.html for more details.

The actual build is then simple as running `gbp buildpackage`. That will produce a new package under `../build-area/`.
