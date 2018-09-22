## SFGO 

Client for [StandardFile](https://standardfile.org) written in golang

Implemented the bare minimum to make it work. Do not use for production API might change at any time.

Working:
* Sync with server
* Decrypt item
* Update item
* Create new item

TODO:
* Register a user
* Update a user's password

### Example

```golang
package main

import (
	sf "github.com/VictorNine/sfgo"
	"fmt"
)

func main() {
	sess = sf.NewSession(
		"https://sync.standardnotes.org",
		"## YOUR EMAIL ##",
	)

	err := sess.Signin("## YOUR PASSWORD ##")
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Login successful!")

	items, _ := sess.Sync()

	fmt.Printf("%+v\n", items)
}
```
