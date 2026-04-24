@echo off
git reset --soft HEAD~1
git checkout -t origin/temp || git checkout temp || git checkout -b temp
git add .
git commit -m "Apply security vulnerability patches and fixes"
git push origin temp
