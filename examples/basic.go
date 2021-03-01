package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/rsclarke/go-nucleus/nucleus"
)

func main() {
	tp := nucleus.APIKeyTransport{
		APIKey: os.Getenv("NUCLEUS_API_KEY"),
	}

	client := nucleus.NewClient(os.Getenv("NUCLEUS_ORG"), tp.Client())
	ctx := context.Background()

	projects, _, err := client.Projects.ListProjects(ctx)
	if err != nil {
		log.Fatalln(err)
	}

	// Print all project names
	for _, project := range projects {
		fmt.Println(project.Name)
	}
}
