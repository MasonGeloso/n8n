<template>
	<div
		:class="{
			'node-settings': true,
			dragging: dragging,
		}"
		@keydown.stop
	>
		<div :class="$style.header">
			<div class="header-side-menu">
				<NodeTitle
					v-if="node"
					class="node-name"
					:modelValue="node.name"
					:nodeType="nodeType"
					:readOnly="isReadOnly"
					@update:modelValue="nameChanged"
				></NodeTitle>
				<div v-if="isExecutable">
					<NodeExecuteButton
						v-if="!blockUI && node && nodeValid"
						data-test-id="node-execute-button"
						:nodeName="node.name"
						:disabled="outputPanelEditMode.enabled && !isTriggerNode"
						size="small"
						telemetrySource="parameters"
						@execute="onNodeExecute"
						@stopExecution="onStopExecution"
					/>
				</div>
			</div>
			<NodeSettingsTabs
				v-if="node && nodeValid"
				v-model="openPanel"
				:nodeType="nodeType"
				:sessionId="sessionId"
			/>
		</div>
		<div class="node-is-not-valid" v-if="node && !nodeValid">
			<p :class="$style.warningIcon">
				<font-awesome-icon icon="exclamation-triangle" />
			</p>
			<div class="missingNodeTitleContainer mt-s mb-xs">
				<n8n-text size="large" color="text-dark" bold>
					{{ $locale.baseText('nodeSettings.communityNodeUnknown.title') }}
				</n8n-text>
			</div>
			<div v-if="isCommunityNode" :class="$style.descriptionContainer">
				<div class="mb-l">
					<i18n-t
						keypath="nodeSettings.communityNodeUnknown.description"
						tag="span"
						@click="onMissingNodeTextClick"
					>
						<template #action>
							<a
								:href="`https://www.npmjs.com/package/${node.type.split('.')[0]}`"
								target="_blank"
								>{{ node.type.split('.')[0] }}</a
							>
						</template>
					</i18n-t>
				</div>
				<n8n-link
					:to="COMMUNITY_NODES_INSTALLATION_DOCS_URL"
					@click="onMissingNodeLearnMoreLinkClick"
				>
					{{ $locale.baseText('nodeSettings.communityNodeUnknown.installLink.text') }}
				</n8n-link>
			</div>
			<i18n-t v-else keypath="nodeSettings.nodeTypeUnknown.description" tag="span">
				<template #action>
					<a
						:href="CUSTOM_NODES_DOCS_URL"
						target="_blank"
						v-text="$locale.baseText('nodeSettings.nodeTypeUnknown.description.customNode')"
					/>
				</template>
			</i18n-t>
		</div>
		<div class="node-parameters-wrapper" data-test-id="node-parameters" v-if="node && nodeValid">
			<n8n-notice
				v-if="hasForeignCredential"
				:content="
					$locale.baseText('nodeSettings.hasForeignCredential', {
						interpolate: { owner: credentialOwnerName },
					})
				"
			/>
			<div v-show="openPanel === 'params'">
				<node-webhooks :node="node" :nodeType="nodeType" />

				<parameter-input-list
					v-if="nodeValuesInitialized"
					:parameters="parametersNoneSetting"
					:hideDelete="true"
					:nodeValues="nodeValues"
					:isReadOnly="isReadOnly"
					:hiddenIssuesInputs="hiddenIssuesInputs"
					path="parameters"
					@valueChanged="valueChanged"
					@activate="onWorkflowActivate"
					@parameterBlur="onParameterBlur"
				>
					<node-credentials
						:node="node"
						:readonly="isReadOnly"
						:showAll="true"
						@credentialSelected="credentialSelected"
						@valueChanged="valueChanged"
						@blur="onParameterBlur"
						:hide-issues="hiddenIssuesInputs.includes('credentials')"
					/>
				</parameter-input-list>
				<div v-if="parametersNoneSetting.length === 0" class="no-parameters">
					<n8n-text>
						{{ $locale.baseText('nodeSettings.thisNodeDoesNotHaveAnyParameters') }}
					</n8n-text>
				</div>

				<div
					v-if="isCustomApiCallSelected(nodeValues)"
					class="parameter-item parameter-notice"
					data-test-id="node-parameters-http-notice"
				>
					<n8n-notice
						:content="
							$locale.baseText('nodeSettings.useTheHttpRequestNode', {
								interpolate: { nodeTypeDisplayName: nodeType.displayName },
							})
						"
					/>
				</div>
			</div>
			<div v-show="openPanel === 'settings'">
				<parameter-input-list
					:parameters="parametersSetting"
					:nodeValues="nodeValues"
					:isReadOnly="isReadOnly"
					:hiddenIssuesInputs="hiddenIssuesInputs"
					path="parameters"
					@valueChanged="valueChanged"
					@parameterBlur="onParameterBlur"
				/>
				<parameter-input-list
					:parameters="nodeSettings"
					:hideDelete="true"
					:nodeValues="nodeValues"
					:isReadOnly="isReadOnly"
					:hiddenIssuesInputs="hiddenIssuesInputs"
					path=""
					@valueChanged="valueChanged"
					@parameterBlur="onParameterBlur"
				/>
			</div>
		</div>
		<n8n-block-ui :show="blockUI" />
	</div>
</template>

<script lang="ts">
import type { PropType } from 'vue';
import { defineComponent } from 'vue';
import { mapStores } from 'pinia';
import type {
	INodeTypeDescription,
	INodeParameters,
	INodeProperties,
	NodeParameterValue,
} from 'n8n-workflow';
import { NodeHelpers, NodeConnectionType, deepCopy } from 'n8n-workflow';
import type {
	INodeUi,
	INodeUpdatePropertiesInformation,
	IUpdateInformation,
	IUsedCredential,
} from '@/Interface';

import {
	COMMUNITY_NODES_INSTALLATION_DOCS_URL,
	CUSTOM_NODES_DOCS_URL,
	MAIN_NODE_PANEL_WIDTH,
	IMPORT_CURL_MODAL_KEY,
} from '@/constants';

import NodeTitle from '@/components/NodeTitle.vue';
import ParameterInputList from '@/components/ParameterInputList.vue';
import NodeCredentials from '@/components/NodeCredentials.vue';
import NodeSettingsTabs from '@/components/NodeSettingsTabs.vue';
import NodeWebhooks from '@/components/NodeWebhooks.vue';
import { get, set, unset } from 'lodash-es';

import { externalHooks } from '@/mixins/externalHooks';
import { nodeHelpers } from '@/mixins/nodeHelpers';

import NodeExecuteButton from './NodeExecuteButton.vue';
import { isCommunityPackageName } from '@/utils';
import { useUIStore } from '@/stores/ui.store';
import { useWorkflowsStore } from '@/stores/workflows.store';
import { useNDVStore } from '@/stores/ndv.store';
import { useNodeTypesStore } from '@/stores/nodeTypes.store';
import { useHistoryStore } from '@/stores/history.store';
import { RenameNodeCommand } from '@/models/history';
import useWorkflowsEEStore from '@/stores/workflows.ee.store';
import { useCredentialsStore } from '@/stores/credentials.store';
import type { EventBus } from 'n8n-design-system';

export default defineComponent({
	name: 'NodeSettings',
	mixins: [externalHooks, nodeHelpers],
	components: {
		NodeTitle,
		NodeCredentials,
		ParameterInputList,
		NodeSettingsTabs,
		NodeWebhooks,
		NodeExecuteButton,
	},
	computed: {
		...mapStores(
			useHistoryStore,
			useNodeTypesStore,
			useNDVStore,
			useUIStore,
			useCredentialsStore,
			useWorkflowsStore,
			useWorkflowsEEStore,
		),
		isCurlImportModalOpen(): boolean {
			return this.uiStore.isModalOpen(IMPORT_CURL_MODAL_KEY);
		},
		isReadOnly(): boolean {
			return this.readOnly || this.hasForeignCredential;
		},
		isExecutable(): boolean {
			if (this.nodeType && this.node) {
				const workflow = this.workflowsStore.getCurrentWorkflow();
				const workflowNode = workflow.getNode(this.node.name);
				const inputs = NodeHelpers.getNodeInputs(workflow, workflowNode!, this.nodeType);
				const inputNames = NodeHelpers.getConnectionTypes(inputs);

				if (!inputNames.includes(NodeConnectionType.Main) && !this.isTriggerNode) {
					return false;
				}
			}

			return this.executable || this.hasForeignCredential;
		},
		nodeTypeName(): string {
			if (this.nodeType) {
				const shortNodeType = this.$locale.shortNodeType(this.nodeType.name);

				return this.$locale.headerText({
					key: `headers.${shortNodeType}.displayName`,
					fallback: this.nodeType.name,
				});
			}

			return '';
		},
		nodeTypeDescription(): string {
			if (this.nodeType?.description) {
				const shortNodeType = this.$locale.shortNodeType(this.nodeType.name);

				return this.$locale.headerText({
					key: `headers.${shortNodeType}.description`,
					fallback: this.nodeType.description,
				});
			} else {
				return this.$locale.baseText('nodeSettings.noDescriptionFound');
			}
		},
		headerStyle(): object {
			if (!this.node) {
				return {};
			}

			return {
				'background-color': this.node.color,
			};
		},
		node(): INodeUi | null {
			return this.ndvStore.activeNode;
		},
		parametersSetting(): INodeProperties[] {
			return this.parameters.filter((item) => {
				return item.isNodeSetting;
			});
		},
		parametersNoneSetting(): INodeProperties[] {
			return this.parameters.filter((item) => {
				return !item.isNodeSetting;
			});
		},
		parameters(): INodeProperties[] {
			if (this.nodeType === null) {
				return [];
			}

			return this.nodeType.properties;
		},
		outputPanelEditMode(): { enabled: boolean; value: string } {
			return this.ndvStore.outputPanelEditMode;
		},
		isCommunityNode(): boolean {
			return isCommunityPackageName(this.node?.type);
		},
		isTriggerNode(): boolean {
			return this.nodeTypesStore.isTriggerNode(this.node?.type);
		},
		workflowOwnerName(): string {
			return this.workflowsEEStore.getWorkflowOwnerName(`${this.workflowsStore.workflowId}`);
		},
		hasForeignCredential(): boolean {
			return this.foreignCredentials.length > 0;
		},
		usedCredentials(): IUsedCredential[] {
			return Object.values(this.workflowsStore.usedCredentials).filter((credential) => {
				return Object.values(this.node?.credentials || []).find((nodeCredential) => {
					return nodeCredential.id === credential.id;
				});
			});
		},
		credentialOwnerName(): string {
			const credential = this.usedCredentials
				? Object.values(this.usedCredentials).find((credential) => {
						return credential.id === this.foreignCredentials[0];
				  })
				: undefined;

			return this.credentialsStore.getCredentialOwnerName(credential);
		},
	},
	props: {
		eventBus: {
			type: Object as PropType<EventBus>,
		},
		dragging: {
			type: Boolean,
		},
		sessionId: {
			type: String,
		},
		nodeType: {
			type: Object as PropType<INodeTypeDescription>,
		},
		readOnly: {
			type: Boolean,
			default: false,
		},
		foreignCredentials: {
			type: Array as PropType<string[]>,
			default: () => [],
		},
		blockUI: {
			type: Boolean,
			default: false,
		},
		executable: {
			type: Boolean,
			default: true,
		},
	},
	data() {
		return {
			nodeValid: true,
			nodeColor: null,
			openPanel: 'params',
			nodeValues: {
				color: '#ff0000',
				alwaysOutputData: false,
				executeOnce: false,
				notesInFlow: false,
				onError: 'stopWorkflow',
				retryOnFail: false,
				maxTries: 3,
				waitBetweenTries: 1000,
				notes: '',
				parameters: {},
			} as INodeParameters,
			nodeValuesInitialized: false, // Used to prevent nodeValues from being overwritten by defaults on reopening ndv

			nodeSettings: [] as INodeProperties[],
			COMMUNITY_NODES_INSTALLATION_DOCS_URL,
			CUSTOM_NODES_DOCS_URL,
			MAIN_NODE_PANEL_WIDTH,
			hiddenIssuesInputs: [] as string[],
		};
	},
	watch: {
		node(newNode, oldNode) {
			this.setNodeValues();
		},
		isCurlImportModalOpen(newValue, oldValue) {
			if (newValue === false) {
				let parameters = this.uiStore.getHttpNodeParameters || '';

				if (!parameters) return;

				try {
					parameters = JSON.parse(parameters) as {
						[key: string]: any;
					};

					//@ts-ignore
					this.valueChanged({
						node: this.node.name,
						name: 'parameters',
						value: parameters,
					});

					this.uiStore.setHttpNodeParameters({ name: IMPORT_CURL_MODAL_KEY, parameters: '' });
				} catch {}
			}
		},
	},
	methods: {
		populateHiddenIssuesSet() {
			if (!this.node || !this.workflowsStore.isNodePristine(this.node.name)) return;

			this.hiddenIssuesInputs.push('credentials');
			this.parametersNoneSetting.forEach((parameter) => {
				this.hiddenIssuesInputs.push(parameter.name);
			});

			this.workflowsStore.setNodePristine(this.node.name, false);
		},
		populateSettings() {
			if (this.isExecutable && !this.isTriggerNode) {
				this.nodeSettings.push(
					...([
						{
							displayName: this.$locale.baseText('nodeSettings.alwaysOutputData.displayName'),
							name: 'alwaysOutputData',
							type: 'boolean',
							default: false,
							noDataExpression: true,
							description: this.$locale.baseText('nodeSettings.alwaysOutputData.description'),
						},
						{
							displayName: this.$locale.baseText('nodeSettings.executeOnce.displayName'),
							name: 'executeOnce',
							type: 'boolean',
							default: false,
							noDataExpression: true,
							description: this.$locale.baseText('nodeSettings.executeOnce.description'),
						},
						{
							displayName: this.$locale.baseText('nodeSettings.retryOnFail.displayName'),
							name: 'retryOnFail',
							type: 'boolean',
							default: false,
							noDataExpression: true,
							description: this.$locale.baseText('nodeSettings.retryOnFail.description'),
						},
						{
							displayName: this.$locale.baseText('nodeSettings.maxTries.displayName'),
							name: 'maxTries',
							type: 'number',
							typeOptions: {
								minValue: 2,
								maxValue: 5,
							},
							default: 3,
							displayOptions: {
								show: {
									retryOnFail: [true],
								},
							},
							noDataExpression: true,
							description: this.$locale.baseText('nodeSettings.maxTries.description'),
						},
						{
							displayName: this.$locale.baseText('nodeSettings.waitBetweenTries.displayName'),
							name: 'waitBetweenTries',
							type: 'number',
							typeOptions: {
								minValue: 0,
								maxValue: 5000,
							},
							default: 1000,
							displayOptions: {
								show: {
									retryOnFail: [true],
								},
							},
							noDataExpression: true,
							description: this.$locale.baseText('nodeSettings.waitBetweenTries.description'),
						},
						{
							displayName: this.$locale.baseText('nodeSettings.onError.displayName'),
							name: 'onError',
							type: 'options',
							options: [
								{
									name: this.$locale.baseText(
										'nodeSettings.onError.options.stopWorkflow.displayName',
									),
									value: 'stopWorkflow',
									description: this.$locale.baseText(
										'nodeSettings.onError.options.stopWorkflow.description',
									),
								},
								{
									name: this.$locale.baseText(
										'nodeSettings.onError.options.continueRegularOutput.displayName',
									),
									value: 'continueRegularOutput',
									description: this.$locale.baseText(
										'nodeSettings.onError.options.continueRegularOutput.description',
									),
								},
								{
									name: this.$locale.baseText(
										'nodeSettings.onError.options.continueErrorOutput.displayName',
									),
									value: 'continueErrorOutput',
									description: this.$locale.baseText(
										'nodeSettings.onError.options.continueErrorOutput.description',
									),
								},
							],
							default: 'stopWorkflow',
							noDataExpression: true,
							description: this.$locale.baseText('nodeSettings.onError.description'),
						},
					] as INodeProperties[]),
				);
			}
			this.nodeSettings.push(
				...([
					{
						displayName: this.$locale.baseText('nodeSettings.notes.displayName'),
						name: 'notes',
						type: 'string',
						typeOptions: {
							rows: 5,
						},
						default: '',
						noDataExpression: true,
						description: this.$locale.baseText('nodeSettings.notes.description'),
					},
					{
						displayName: this.$locale.baseText('nodeSettings.notesInFlow.displayName'),
						name: 'notesInFlow',
						type: 'boolean',
						default: false,
						noDataExpression: true,
						description: this.$locale.baseText('nodeSettings.notesInFlow.description'),
					},
				] as INodeProperties[]),
			);
		},
		onParameterBlur(parameterName: string) {
			this.hiddenIssuesInputs = this.hiddenIssuesInputs.filter((name) => name !== parameterName);
		},
		onWorkflowActivate() {
			this.hiddenIssuesInputs = [];
			this.$emit('activate');
		},
		onNodeExecute() {
			this.hiddenIssuesInputs = [];
			this.$emit('execute');
		},
		setValue(name: string, value: NodeParameterValue) {
			const nameParts = name.split('.');
			let lastNamePart: string | undefined = nameParts.pop();

			let isArray = false;
			if (lastNamePart !== undefined && lastNamePart.includes('[')) {
				// It includes an index so we have to extract it
				const lastNameParts = lastNamePart.match(/(.*)\[(\d+)\]$/);
				if (lastNameParts) {
					nameParts.push(lastNameParts[1]);
					lastNamePart = lastNameParts[2];
					isArray = true;
				}
			}

			// Set the value so that everything updates correctly in the UI
			if (nameParts.length === 0) {
				// Data is on top level
				if (value === null) {
					// Property should be deleted
					const { [lastNamePart]: removedNodeValue, ...remainingNodeValues } = this.nodeValues;
					this.nodeValues = remainingNodeValues;
				} else {
					// Value should be set
					this.nodeValues = {
						...this.nodeValues,
						[lastNamePart as string]: value,
					};
				}
			} else {
				// Data is on lower level
				if (value === null) {
					// Property should be deleted
					let tempValue = get(this.nodeValues, nameParts.join('.')) as
						| INodeParameters
						| INodeParameters[];

					const { [lastNamePart]: removedNodeValue, ...remainingNodeValues } = tempValue;
					tempValue = remainingNodeValues;

					if (isArray && (tempValue as INodeParameters[]).length === 0) {
						// If a value from an array got delete and no values are left
						// delete also the parent
						lastNamePart = nameParts.pop();
						tempValue = get(this.nodeValues, nameParts.join('.')) as INodeParameters;
						const { [lastNamePart]: removedArrayNodeValue, ...remainingArrayNodeValues } =
							tempValue;
						tempValue = remainingArrayNodeValues;
					}
				} else {
					// Value should be set
					if (typeof value === 'object') {
						set(
							get(this.nodeValues, nameParts.join('.')) as Record<string, unknown>,
							lastNamePart as string,
							deepCopy(value),
						);
					} else {
						set(
							get(this.nodeValues, nameParts.join('.')) as Record<string, unknown>,
							lastNamePart as string,
							value,
						);
					}
				}
			}

			this.nodeValues = { ...this.nodeValues };
		},
		credentialSelected(updateInformation: INodeUpdatePropertiesInformation) {
			// Update the values on the node
			this.workflowsStore.updateNodeProperties(updateInformation);

			const node = this.workflowsStore.getNodeByName(updateInformation.name);

			if (node) {
				// Update the issues
				this.updateNodeCredentialIssues(node);
			}

			void this.$externalHooks().run('nodeSettings.credentialSelected', { updateInformation });
		},
		nameChanged(name: string) {
			if (this.node) {
				this.historyStore.pushCommandToUndo(new RenameNodeCommand(this.node.name, name));
			}
			// @ts-ignore
			this.valueChanged({
				value: name,
				name: 'name',
			});
		},
		valueChanged(parameterData: IUpdateInformation) {
			let newValue: NodeParameterValue;

			if (parameterData.hasOwnProperty('value')) {
				// New value is given
				newValue = parameterData.value as string | number;
			} else {
				// Get new value from nodeData where it is set already
				newValue = get(this.nodeValues, parameterData.name) as NodeParameterValue;
			}
			// Save the node name before we commit the change because
			// we need the old name to rename the node properly
			const nodeNameBefore = parameterData.node || this.node?.name;
			const node = this.workflowsStore.getNodeByName(nodeNameBefore);

			if (node === null) {
				return;
			}

			if (parameterData.name === 'onError') {
				// If that parameter changes, we need to redraw the connections, as the error output may need to be added or removed
				this.$emit('redrawRequired');
			}

			if (parameterData.name === 'name') {
				// Name of node changed so we have to set also the new node name as active

				// Update happens in NodeView so emit event
				const sendData = {
					value: newValue,
					oldValue: nodeNameBefore,
					name: parameterData.name,
				};
				this.$emit('valueChanged', sendData);
			} else if (parameterData.name === 'parameters') {
				const nodeType = this.nodeTypesStore.getNodeType(node.type, node.typeVersion);
				if (!nodeType) {
					return;
				}

				// Get only the parameters which are different to the defaults
				let nodeParameters = NodeHelpers.getNodeParameters(
					nodeType.properties,
					node.parameters,
					false,
					false,
					node,
				);

				const oldNodeParameters = Object.assign({}, nodeParameters);

				// Copy the data because it is the data of vuex so make sure that
				// we do not edit it directly
				nodeParameters = deepCopy(nodeParameters);

				for (const parameterName of Object.keys(parameterData.value)) {
					//@ts-ignore
					newValue = parameterData.value[parameterName];

					// Remove the 'parameters.' from the beginning to just have the
					// actual parameter name
					const parameterPath = parameterName.split('.').slice(1).join('.');

					// Check if the path is supposed to change an array and if so get
					// the needed data like path and index
					const parameterPathArray = parameterPath.match(/(.*)\[(\d+)\]$/);

					// Apply the new value
					//@ts-ignore
					if (parameterData[parameterName] === undefined && parameterPathArray !== null) {
						// Delete array item
						const path = parameterPathArray[1];
						const index = parameterPathArray[2];
						const data = get(nodeParameters, path);

						if (Array.isArray(data)) {
							data.splice(parseInt(index, 10), 1);
							set(nodeParameters as object, path, data);
						}
					} else {
						if (newValue === undefined) {
							unset(nodeParameters as object, parameterPath);
						} else {
							set(nodeParameters as object, parameterPath, newValue);
						}
					}

					void this.$externalHooks().run('nodeSettings.valueChanged', {
						parameterPath,
						newValue,
						parameters: this.parameters,
						oldNodeParameters,
					});
				}

				// Get the parameters with the now new defaults according to the
				// from the user actually defined parameters
				nodeParameters = NodeHelpers.getNodeParameters(
					nodeType.properties,
					nodeParameters as INodeParameters,
					true,
					false,
					node,
				);

				for (const key of Object.keys(nodeParameters as object)) {
					if (nodeParameters && nodeParameters[key] !== null && nodeParameters[key] !== undefined) {
						this.setValue(`parameters.${key}`, nodeParameters[key] as string);
					}
				}

				if (nodeParameters) {
					const updateInformation: IUpdateInformation = {
						name: node.name,
						value: nodeParameters,
					};

					this.workflowsStore.setNodeParameters(updateInformation);

					this.updateNodeParameterIssuesByName(node.name);
					this.updateNodeCredentialIssuesByName(node.name);
				}
			} else if (parameterData.name.startsWith('parameters.')) {
				// A node parameter changed

				const nodeType = this.nodeTypesStore.getNodeType(node.type, node.typeVersion);
				if (!nodeType) {
					return;
				}

				// Get only the parameters which are different to the defaults
				let nodeParameters = NodeHelpers.getNodeParameters(
					nodeType.properties,
					node.parameters,
					false,
					false,
					node,
				);
				const oldNodeParameters = Object.assign({}, nodeParameters);

				// Copy the data because it is the data of vuex so make sure that
				// we do not edit it directly
				nodeParameters = deepCopy(nodeParameters);

				// Remove the 'parameters.' from the beginning to just have the
				// actual parameter name
				const parameterPath = parameterData.name.split('.').slice(1).join('.');

				// Check if the path is supposed to change an array and if so get
				// the needed data like path and index
				const parameterPathArray = parameterPath.match(/(.*)\[(\d+)\]$/);

				// Apply the new value
				if (parameterData.value === undefined && parameterPathArray !== null) {
					// Delete array item
					const path = parameterPathArray[1];
					const index = parameterPathArray[2];
					const data = get(nodeParameters, path);

					if (Array.isArray(data)) {
						data.splice(parseInt(index, 10), 1);
						set(nodeParameters as object, path, data);
					}
				} else {
					if (newValue === undefined) {
						unset(nodeParameters as object, parameterPath);
					} else {
						set(nodeParameters as object, parameterPath, newValue);
					}
				}

				// Get the parameters with the now new defaults according to the
				// from the user actually defined parameters
				nodeParameters = NodeHelpers.getNodeParameters(
					nodeType.properties,
					nodeParameters as INodeParameters,
					true,
					false,
					node,
				);

				for (const key of Object.keys(nodeParameters as object)) {
					if (nodeParameters && nodeParameters[key] !== null && nodeParameters[key] !== undefined) {
						this.setValue(`parameters.${key}`, nodeParameters[key] as string);
					}
				}

				// Update the data in vuex
				const updateInformation: IUpdateInformation = {
					name: node.name,
					value: nodeParameters,
				};

				this.workflowsStore.setNodeParameters(updateInformation);

				void this.$externalHooks().run('nodeSettings.valueChanged', {
					parameterPath,
					newValue,
					parameters: this.parameters,
					oldNodeParameters,
				});

				this.updateNodeParameterIssuesByName(node.name);
				this.updateNodeCredentialIssuesByName(node.name);
				this.$telemetry.trackNodeParametersValuesChange(nodeType.name, parameterData);
			} else {
				// A property on the node itself changed

				// Update data in settings
				this.nodeValues = {
					...this.nodeValues,
					[parameterData.name]: newValue,
				};

				// Update data in vuex
				const updateInformation = {
					name: node.name,
					key: parameterData.name,
					value: newValue,
				};

				this.workflowsStore.setNodeValue(updateInformation);
			}
		},
		/**
		 * Sets the values of the active node in the internal settings variables
		 */
		setNodeValues() {
			// No node selected
			if (!this.node) {
				this.nodeValuesInitialized = true;
				return;
			}

			if (this.nodeType !== null) {
				this.nodeValid = true;

				const foundNodeSettings = [];
				if (this.node.color) {
					foundNodeSettings.push('color');
					this.nodeValues = {
						...this.nodeValues,
						color: this.node.color,
					};
				}

				if (this.node.notes) {
					foundNodeSettings.push('notes');
					this.nodeValues = {
						...this.nodeValues,
						notes: this.node.notes,
					};
				}

				if (this.node.alwaysOutputData) {
					foundNodeSettings.push('alwaysOutputData');
					this.nodeValues = {
						...this.nodeValues,
						alwaysOutputData: this.node.alwaysOutputData,
					};
				}

				if (this.node.executeOnce) {
					foundNodeSettings.push('executeOnce');
					this.nodeValues = {
						...this.nodeValues,
						executeOnce: this.node.executeOnce,
					};
				}

				if (this.node.continueOnFail) {
					foundNodeSettings.push('onError');
					this.nodeValues = {
						...this.nodeValues,
						onError: 'continueRegularOutput',
					};
				}

				if (this.node.onError) {
					foundNodeSettings.push('onError');
					this.nodeValues = {
						...this.nodeValues,
						onError: this.node.onError,
					};
				}

				if (this.node.notesInFlow) {
					foundNodeSettings.push('notesInFlow');
					this.nodeValues = {
						...this.nodeValues,
						notesInFlow: this.node.notesInFlow,
					};
				}

				if (this.node.retryOnFail) {
					foundNodeSettings.push('retryOnFail');
					this.nodeValues = {
						...this.nodeValues,
						retryOnFail: this.node.retryOnFail,
					};
				}

				if (this.node.maxTries) {
					foundNodeSettings.push('maxTries');
					this.nodeValues = {
						...this.nodeValues,
						maxTries: this.node.maxTries,
					};
				}

				if (this.node.waitBetweenTries) {
					foundNodeSettings.push('waitBetweenTries');
					this.nodeValues = {
						...this.nodeValues,
						waitBetweenTries: this.node.waitBetweenTries,
					};
				}

				// Set default node settings
				for (const nodeSetting of this.nodeSettings) {
					if (!foundNodeSettings.includes(nodeSetting.name)) {
						// Set default value
						this.nodeValues = {
							...this.nodeValues,
							[nodeSetting.name]: nodeSetting.default,
						};
					}
				}

				this.nodeValues = {
					...this.nodeValues,
					parameters: deepCopy(this.node.parameters),
				};
			} else {
				this.nodeValid = false;
			}

			this.nodeValuesInitialized = true;
		},
		onMissingNodeTextClick(event: MouseEvent) {
			if ((event.target as Element).localName === 'a') {
				this.$telemetry.track('user clicked cnr browse button', {
					source: 'cnr missing node modal',
				});
			}
		},
		onMissingNodeLearnMoreLinkClick() {
			this.$telemetry.track('user clicked cnr docs link', {
				source: 'missing node modal source',
				package_name: this.node?.type.split('.')[0],
				node_type: this.node?.type,
			});
		},
		onStopExecution() {
			this.$emit('stopExecution');
		},
		openSettings() {
			this.openPanel = 'settings';
		},
	},
	mounted() {
		this.populateHiddenIssuesSet();
		this.populateSettings();
		this.setNodeValues();
		this.eventBus?.on('openSettings', this.openSettings);

		this.updateNodeParameterIssues(this.node as INodeUi, this.nodeType);
	},
	beforeUnmount() {
		this.eventBus?.off('openSettings', this.openSettings);
	},
});
</script>

<style lang="scss" module>
.header {
	background-color: var(--color-background-base);
}

.warningIcon {
	color: var(--color-text-lighter);
	font-size: var(--font-size-2xl);
}

.descriptionContainer {
	display: flex;
	flex-direction: column;
}
</style>

<style lang="scss" scoped>
.node-settings {
	display: flex;
	flex-direction: column;
	overflow: hidden;
	background-color: var(--color-background-xlight);
	height: 100%;
	width: 100%;

	.no-parameters {
		margin-top: var(--spacing-xs);
	}

	.header-side-menu {
		padding: var(--spacing-s) var(--spacing-s) var(--spacing-s) var(--spacing-s);
		font-size: var(--font-size-l);
		display: flex;

		.node-name {
			padding-top: var(--spacing-5xs);
			flex-grow: 1;
		}
	}

	.node-is-not-valid {
		height: 75%;
		padding: 10px;
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		text-align: center;
		line-height: var(--font-line-height-regular);
	}

	.node-parameters-wrapper {
		overflow-y: auto;
		padding: 0 var(--spacing-m) 200px var(--spacing-m);
	}

	&.dragging {
		border-color: var(--color-primary);
		box-shadow: 0px 6px 16px rgba(255, 74, 51, 0.15);
	}
}

.parameter-content {
	font-size: 0.9em;
	margin-right: -15px;
	margin-left: -15px;
	input {
		width: calc(100% - 35px);
		padding: 5px;
	}
	select {
		width: calc(100% - 20px);
		padding: 5px;
	}

	&:before {
		display: table;
		content: ' ';
		position: relative;
		box-sizing: border-box;
		clear: both;
	}
}

.parameter-wrapper {
	padding: 0 1em;
}

.color-reset-button-wrapper {
	position: relative;
}
.color-reset-button {
	position: absolute;
	right: 7px;
	top: -25px;
}

.parameter-value {
	input.expression {
		border-style: dashed;
		border-color: #ff9600;
		display: inline-block;
		position: relative;
		width: 100%;
		box-sizing: border-box;
		background-color: #793300;
	}
}
</style>
