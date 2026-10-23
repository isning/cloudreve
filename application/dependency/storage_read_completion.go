package dependency

import "github.com/cloudreve/Cloudreve/v4/inventory"

func (d *dependency) StorageReadCompletions() *inventory.StorageReadCompletions {
	d.readCompletionsOnce.Do(func() {
		d.readCompletions = inventory.NewStorageReadCompletions(d.DBClient(), d.Logger())
	})
	return d.readCompletions
}
