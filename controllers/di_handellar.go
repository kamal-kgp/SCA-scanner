package controllers

import (
	"fmt"
	"os"
	"os/exec"
	"strings" 
	"time"
	"encoding/json"

	"github.com/gofiber/fiber/v2"
)

type ScanResult struct {
    Status  string `json:"status"`
    Message string `json:"message"`
    Data    interface{} `json:"data"` 
}

func HandleRequest(c *fiber.Ctx) error {

	file, err := c.FormFile("file")
	if err != nil {
		fmt.Printf("%v\n", err)
		return c.Status(fiber.StatusBadRequest).SendString("Unable to parse form")
	}

	newFileName := fmt.Sprintf("%s_%s", time.Now().Format("20060102150405"), file.Filename)
	destination := fmt.Sprintf("./uploads/%s", newFileName)

	if err := c.SaveFile(file, destination); err != nil {
		fmt.Printf("%v\n", err)
		return c.Status(fiber.StatusBadRequest).SendString("Unable to save file")
	}

	// Run Trivy scan on the saved file
	errTrivy := runTrivyScan(newFileName, destination)

	if errTrivy != nil {
		delErr := deleteFile(destination)
		if delErr != nil {
			fmt.Printf("delete file failed: %s", delErr)
		}
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to run Trivy scan")
	}

	// Read the scan result file
    scanData, errRead := os.ReadFile(fmt.Sprintf("./scan_files/%s_%s", strings.Split(newFileName, ".")[0], ".json"))
    if errRead != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(ScanResult{Status: "error", Message: "Failed to read scan result"})
    }

	var jsonData map[string]interface{} // or desired data structure
    if err := json.Unmarshal(scanData, &jsonData); err != nil {
        // Handle potential unmarshalling error (optional)
        return c.Status(fiber.StatusInternalServerError).JSON(ScanResult{Status: "error", Message: "Failed to parse scan result"})
    }

    // Send the scan data as JSON
    c.Status(fiber.StatusOK).JSON(ScanResult{Status: "success", Message: "Scan completed", Data: jsonData})

    // Delete the scan result file after sending the response
    if err := os.Remove(fmt.Sprintf("./scan_files/%s_%s", strings.Split(newFileName, ".")[0], ".json")); err != nil {
        fmt.Printf("Failed to delete file: %v\n", err)
    }

	return nil 
}

func runTrivyScan(o_fname string, upload_fname string) error {
	//create json file to upload scan data
	parts := strings.Split(o_fname, ".")
	name := parts[0]

	scan_fname := fmt.Sprintf("%s_%s", name, ".json")

	dst := fmt.Sprintf("./scan_files/%s", scan_fname)
	// Run Trivy scan command
	cmd := exec.Command("trivy", "fs", upload_fname, "-f", "json", "-o", dst)
	_, errTrivy := cmd.CombinedOutput()
	if errTrivy != nil {
		delErr := deleteFile(upload_fname)
		if delErr != nil {
			fmt.Printf("delete file failed: %s", delErr)
		}
		return fmt.Errorf("trivy scan failed: %s", errTrivy)
	}

	delErr := deleteFile(upload_fname)
	if delErr != nil {
		fmt.Printf("delete file failed: %s", delErr)
	}

	return nil 
}

func deleteFile(path string) error {
	err := os.Remove(path)
	if err != nil {
		return err
	}
	return nil
}