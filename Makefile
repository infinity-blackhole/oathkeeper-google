.PHONY: deploy-oathkeeper-google-hydrate-token
deploy-oathkeeper-google-hydrate-token:
	gcloud beta functions deploy oathkeeper-google-hydrate-token \
		--gen2 \
		--runtime go116 \
		--trigger-http \
		--entry-point HydrateToken \
		--source . \
		--allow-unauthenticated \
		--env-vars-file .env.yaml
