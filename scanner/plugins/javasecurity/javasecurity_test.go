// Copyright 2024 IBM
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package javasecurity

import (
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func Test_getJDKPath(t *testing.T) {
	type args struct {
		dockerConfig v1.Config
	}
	tests := []struct {
		name      string
		args      args
		wantValue string
		wantOk    bool
	}{
		{
			name: "Test 1",
			args: args{
				dockerConfig: v1.Config{
					Cmd: []string{"java", "-jar", "app.jar"},
				},
			},
			wantValue: "",
			wantOk:    false,
		},
		{
			name: "Test 2",
			args: args{
				dockerConfig: v1.Config{
					Cmd: []string{"java", "-jar", "app.jar"},
					Env: []string{"JAVA_HOME=/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.292.b10-0.el8_4.x86_64"},
				},
			},
			wantValue: "/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.292.b10-0.el8_4.x86_64",
			wantOk:    true,
		},
		{
			name: "Test 3",
			args: args{
				dockerConfig: v1.Config{
					Cmd: []string{"/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.292.b10-0.el8_4.x86_64/bin/java", "-jar", "app.jar"},
				},
			},
			wantValue: "/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.292.b10-0.el8_4.x86_64",
			wantOk:    true,
		},
		{
			name: "Test 4",
			args: args{
				dockerConfig: v1.Config{
					Entrypoint: []string{"/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.292.b10-0.el8_4.x86_64/bin/java", "-jar", "app.jar"},
				},
			},
			wantValue: "/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.292.b10-0.el8_4.x86_64",
			wantOk:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotValue, gotOk := getJDKPath(tt.args.dockerConfig)
			if gotValue != tt.wantValue {
				t.Errorf("getJDKPathFromRunCommand() gotValue = %v, want %v", gotValue, tt.wantValue)
			}
			if gotOk != tt.wantOk {
				t.Errorf("getJDKPathFromRunCommand() gotOk = %v, want %v", gotOk, tt.wantOk)
			}
		})
	}
}
