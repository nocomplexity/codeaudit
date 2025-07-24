# Random Statement 

Codeaudit checks on the use of the `random` module. Checks are done for:
* `random.seed` and
* `random.random`

Too often these functions are not used in the right way!

The pseudo-random generators of the module `random` should not be used for security purposes. 
However this is still too often neglected. 


## More information

* https://docs.python.org/3/library/secrets.html#module-secrets