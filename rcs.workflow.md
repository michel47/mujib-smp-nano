# IMPORTANT NOTE ABOUT RCS WORKFLOW

AI agent discipline to be able to recover from errors

```
rcs diff $file
if $? != 0; then
cp -p $file $file.$$.bak
if rlog -l $file | grep locked; then
echo $? locked
 rlog -l $file | grep locked | grep -v $USER
 if [ $? -eq 0 ]; then
    echo $? $USER
 else
    echo $? not $USER
 fi
else
echo $?  unlocked
 rlog -l $file | grep locked
fi

diff $file.$$.bak $file
rlog -l $file | grep locked
mv -f $file.$$.bak $file
else
rlog -l $file
co -l -f $file
fi

cp -p $file $buffer
edit $buffer # ...
cat $buffer > $file
ci -m"$commit_msg" -w"aiagent" $file
co -u $file
```

PLEASE REMEMBER THIS SO YOU NEVER LOOSE A FILE or BREAK THE CODE

1. check lock with ``rlog -r -l $file`` and look for keyword 'locked', the locks policy set to strict doesn't mean the file is locked
1. never force a lock
2. never remove a file

the test to see if you have the lock is 
```sh
echo you are $USER
rlog -r -l $file | grep locked | grep $USER
echo $? # 1 means you don't have a lock
```
the test to see if the file is locked by someone else
```sh
echo you are $USER
rlog -r -l $file | grep locked | grep -v -e $USER
echo $? # 1 means noone has the lock
```


and if you are in panick you may do a ``ls -ltr ../backups`` to manually recover some saved versions made with ``rename -c``


