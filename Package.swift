// swift-tools-version:5.10
//
//  Package.swift
//  OAuth2
//
//  Created by Pascal Pfiffner on 12/19/15.
//  Copyright 2015 Pascal Pfiffner
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//

import PackageDescription

let strictConcurrency: [SwiftSetting] = [
	.enableExperimentalFeature("StrictConcurrency"),
]

let package = Package(
	name: "OAuth2",
	platforms: [
		.macOS(.v12), .iOS(.v15), .tvOS(.v15), .watchOS(.v8)
	],
	products: [
		.library(name: "OAuth2", targets: ["OAuth2"]),
	],
	dependencies: [],
	targets: [
		.target(name: "OAuth2", swiftSettings: strictConcurrency),
		.testTarget(name: "OAuth2ConcurrencyTests", dependencies: [.target(name: "OAuth2")], swiftSettings: strictConcurrency),
	],
	swiftLanguageVersions: [.v5]
)
