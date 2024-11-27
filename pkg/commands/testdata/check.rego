# METADATA
# title: Bad input data
# description: Just failing rule with input data
# scope: package
# schemas:
# - input: schema["input"]
# custom:
#   severity: LOW
#   service: s3
#   input:
#     selector:
#     - type: cloud
package user.whatever
import data.settings.DS123.foo

deny {
	foo == true
}