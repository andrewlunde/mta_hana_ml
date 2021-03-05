# Build Command:
```
cd mta_hana_ml ; mkdir -p mta_archives ; mbt build -p=cf -t=mta_archives --mtar=hana-ml.mtar
```

# Deploy Command:
```
cf deploy mta_archives/hana-ml.mtar -f
```

# Subsequent Build+Deploy Commands:
```
mbt build -p=cf -t=mta_archives --mtar=hana-ml.mtar ; cf deploy mta_archives/hana-ml.mtar -f
```

# Undeploy Command:
```
cf undeploy hana-ml -f --delete-services
```
