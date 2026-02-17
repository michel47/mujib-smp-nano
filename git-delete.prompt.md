# GIT INSTRUCTION 


here is how to delete a file i(even) after having been commited
```sh
# git-delete: remove/delete a commited file rewrite history ... (right to erasure)
# see also : https://docs.github.com/en/github/authenticating-to-github/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository
file=get_pass.pl
git hash-object $file
sha1=2c8282a1d083c1c8def510bad4dd1dafaff4ac7c
sha1=$(git hash-object $file)
git cat-file -p $sha1 | perl -S $file -16


git stash
#Saved working directory and index state WIP on master: 3d8d6c0 ...
git stash list
git stash show
git log --graph --oneline --all --decorate
file=etc/passwd.clear.txt
file=$sha1
git filter-branch --force --index-filter "git rm --cached --ignore-unmatch $file" \
  --prune-empty --tag-name-filter cat -- --all
  
  git gc --prune=now --aggressive
  git push --force --verbose --dry-run
  git push --force
  
git log --graph --oneline --all --decorate
```

