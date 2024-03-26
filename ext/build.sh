#!/bin/sh

SCRIPT=$(realpath "$0")
BASEDIR=$(dirname "$SCRIPT")
BUILDDIR="$BASEDIR/build"
FFBUILDDIR="$BUILDDIR/ff"
FFEXT="$BUILDDIR/ext_ff.zip"
CHROMEBUILDDIR="$BUILDDIR/chrome"
CHROMEEXT="$BUILDDIR/ext_chrome.zip"

files="$BASEDIR/*js $BASEDIR/*html $BASEDIR/*css $BASEDIR/*png $BASEDIR/_locales/"

[ ! -d "$BUILDDIR" ] && mkdir "$BUILDDIR"

[ -d "$FFBUILDDIR" ] && rm -r "$FFBUILDDIR"
[ -d "$CHROMEBUILDDIR" ] && rm -r "$CHROMEBUILDDIR"
[ -f "$FFEXT" ] && rm "$FFEXT"
[ -f "$CHROMEEXT" ] && rm "$CHROMEEXT"

mkdir "$FFBUILDDIR"
cp -r $files "$FFBUILDDIR"
cp "$BASEDIR/manifest_ff.json" "$FFBUILDDIR/manifest.json"
cd "$FFBUILDDIR"
zip "$FFEXT" ./*
cd -


mkdir "$CHROMEBUILDDIR"
cp -r $files "$CHROMEBUILDDIR"
cp "$BASEDIR/manifest_chrome.json" "$CHROMEBUILDDIR/manifest.json"
cd "$CHROMEBUILDDIR"
zip "$CHROMEEXT" ./*
cd -
